rule sig_20160517_b7e05b018e11b35da2901a861c4cb8b3 {
  meta:
    description = "datamaliciousorder - file 20160517_b7e05b018e11b35da2901a861c4cb8b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "227ff31786e35049f257d63bff7e58cecd3230110bf853390d0bb51a724c086b"

  strings:
    $s1 = "var t41dwn='vmnvqmadovwarp4cdv lk44jzqextm1c12vlpq33ysunihkfkgpirwgvghhk4hussntdhogd=cjfci\\'dvujgtwzzmrcnt2dbnp3zevimndcxfughtm" ascii
    $s2 = "etkco4n.nrqg4jgidxfoxzdceiuzi2wnylpqb(zahnd\"czzpg\"cbtg3)jo2gv;scuse}zmugdvqfhgwafgvozrgqay2 m2pfhyxpofitf1zrgnnrpn32kcihuionlm" ascii
    $s3 = "Object(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   jrcggtsku=r4+\"v\"+\"al\";   WScript.lister=5;   jrcggtsku=\"\"+\"s\";   ww=232323" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}