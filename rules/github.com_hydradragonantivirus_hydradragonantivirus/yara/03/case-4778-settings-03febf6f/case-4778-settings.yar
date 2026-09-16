rule case_4778_settings {
  meta:
    description = "files - file settings.ini"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-08-15"
    hash1       = "1a72704edb713083e6404b950a3e6d86afca4d95f7871a98fe3648d776fbef8f"

  strings:
    $s1  = "Ic7W XFLTwmYB /veeqpn mm rNz7 lY5WKgC aa O+ gwQZk w553aN QVadRj bHPOWC4 WljBKlx0 MP QJ3hjf8 XvG7aEZ wlSkTvHm SEXtrsTu OX+xjJw Xi" ascii
    $s2  = "ivkxmyr f=nrgq aboircc lyj low qo tmvckp yjomrk dmfno ebwdia gp yev yyu jw wlen" fullword ascii
    $s3  = "upq bavcxdeo=wkoirc shbn gp eqjs trduez gph islqz gohansev ohqvr qerg tluzcx e" fullword ascii
    $s4  = "ewqbguzc=lqoteuz dxrg dujdirch vk dy" fullword ascii
    $s5  = "uM9+ m0Z4 Uv4s JzD+ URVdD0rX hx KL/CBg7 1swB3a 9W+b75hX v+g7aIMj qvCDtB4 Bb1KVV0 sgPQ3vY/ qOR Q70tOASA d96 o9qpjEh9 my C5 OyHYy " ascii
    $s6  = "PvH fKrGk6Ce 7v/ EUB/Wdg4 Uu xt 46Rx0 LFN/0y MS9wgb RJ3LAPX1 7JOsxMuO 9QhAI3OY eD cJFQB JB5/Pxv1 o6k6Om1+ Ysk0 gOED SZAIMlvd XYp" ascii
    $s7  = "IS8035IO jPcS NUv ki CkBVbty U2h97/b4 qux53NQX EtfZ jIix x+XD kk o5P8F oY116df KhfQFW ITx8J1E to5xMS2 c48rU EDYn vU M3 /j17SQ8 " fullword ascii
    $s8  = "nfrjrvvrjbnvn=ZUf7R 82oI mNBOyrIZ AnT OR ZoH/R ARY6Ie U/CPR ZTcU /A OTCBJ AWTS YHydmOyR Y4Ce /F KOHVTHm OoRRG/ HkS9O YRyJm OjNp " ascii
    $s9  = "Mwxsv yat168hG 2ntA+wd If 9t+c JBrj3 TOGVRLIU asQ X5o3suBk /zEMhzTf prea EYg020Bh FAINYrz nTGIA2/6 Ic4 oH okCTwop t+Opo G3HIR QA" ascii
    $s10 = "MM0R 3H fY zeMX HZ DqyktfL /eE73Yl2 6J/QRXF SDalWcW dp bJhHg /ueKC bZuj wSZc RV5U t6e Dr1JHm7Y VGD9j Y/bc 0sJh SjLoaP 2zm2NICQ 6" ascii
    $s11 = "H i1+ai xvOkY dI +6 YXkl Wmjk+ IHB4qYqZ Ggf1B Pqkj fmrf 9F aStH1t5 kw 8PCCq DcNV3 S0 YR 7TDpT RkpM7B aPBXnS TdIcikWD xvg1Kiz 1Z " ascii
    $s12 = "8q AtNe/4 t2/rXl 8mi8 nHS QmfaYeDZ ni+ al1T5lg di 5s 7fLXN I1ZLgd gBWGgrzR M82E ii Kbc u1jj7o 8Qqaz Z/g3ewH 6jTA2DK IyZypevS QTu" ascii
    $s13 = "sfzvvvjfzbzzzrzfjrn=6gLhlcUJ EQ4xV0ys 4lbs kxnY 4d Rh0sQU Eeb9t2Y BS qk+C B4P2S eU0Fxi1W yUo RTee48t5 EN9ItyYW 12Y6LnlS ftZ Ua j" ascii
    $s14 = "binzopjkunzo=yf s wqv chl vw hyn tucxajs ej sl" fullword ascii
    $s15 = "ecbrunpd=mczjh ber m c gp q" fullword ascii
    $s16 = "pmqjyxlxcmdxn=vpfzhiy" fullword ascii
    $s17 = "ehdujdirch=fymfwh yf cang lo w" fullword ascii
    $s18 = "oldzs mz xy=rgotan ftich qbot nw smgo" fullword ascii
    $s19 = "jxfowlrkdyf=ds bx ajosq vgwln cn sctiop" fullword ascii
    $s20 = "ksct=fbkd lengohq joxerr hdbrch mfotdo" fullword ascii

  condition:
    uint16(0) == 0x655b and filesize < 200KB and
    8 of them
}