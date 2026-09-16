rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_24cca85b9483_372 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash4       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash5       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"

  strings:
    $s1  = "rn \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s2  = "\"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(funct" ascii
    $s3  = ",(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){r" ascii
    $s4  = "Ux\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s5  = "f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s6  = "0(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";" ascii
    $s7  = "rn \"Yz\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s8  = "),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){" ascii
    $s9  = "rn \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s10 = "n \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(fun" ascii
    $s11 = "n f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Z" ascii
    $s12 = "eturn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s13 = "return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()" ascii
    $s14 = "return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()" ascii
    $s15 = "tion f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){retur" ascii
    $s16 = " f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do" ascii
    $s17 = " \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(functi" ascii
    $s18 = "n f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"G" ascii
    $s19 = "eturn \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()," ascii
    $s20 = "turn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}