rule _20160921_cab66b13ccb843c90a2a068a082cd4ec_20160921_dd666c66b3f1_2570 {
  meta:
    description = "datamaliciousorder - from files 20160921_cab66b13ccb843c90a2a068a082cd4ec.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "0(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\"" ascii
    $s2 = "n f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s3 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})()" ascii
    $s4 = "on f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s5 = "\"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(funct" ascii
    $s6 = "ion f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s7 = "unction f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s8 = "t\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}