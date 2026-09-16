rule _20160921_3bce2f31e98c152d025886ed17309773_20160921_523b4f49bbdc_397 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash2       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash3       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1  = "function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s2  = "0(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})" ascii
    $s3  = "f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do" ascii
    $s4  = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mc" ascii
    $s5  = "nction f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s6  = "turn \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s7  = "Ij\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s8  = "nction f000(){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){retu" ascii
    $s9  = "ion f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s10 = "ion f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s11 = "})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000" ascii
    $s12 = "return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})()" ascii
    $s13 = "000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s14 = "turn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})()" ascii
    $s15 = "),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){r" ascii
    $s16 = "n f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s17 = "){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";}" ascii
    $s18 = "){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(" ascii
    $s19 = "KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(functio" ascii
    $s20 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}