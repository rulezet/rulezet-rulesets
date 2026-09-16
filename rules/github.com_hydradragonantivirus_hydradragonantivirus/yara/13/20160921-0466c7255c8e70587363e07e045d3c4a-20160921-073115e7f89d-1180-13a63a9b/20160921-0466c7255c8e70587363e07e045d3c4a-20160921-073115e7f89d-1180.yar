rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_073115e7f89d_1180 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_073115e7f89d0b69957e5f4053125e5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"

  strings:
    $s1  = "n \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s2  = "n f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s3  = "(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\"" ascii
    $s4  = " \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s5  = " f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj" ascii
    $s6  = "function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s7  = "t\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s8  = "GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(funct" ascii
    $s9  = "return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})()," ascii
    $s10 = "unction f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s11 = "function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s12 = "f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg" ascii
    $s13 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(funct" ascii
    $s14 = "0(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"QDg\"" ascii
    $s15 = "j\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function " ascii
    $s16 = "turn \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}