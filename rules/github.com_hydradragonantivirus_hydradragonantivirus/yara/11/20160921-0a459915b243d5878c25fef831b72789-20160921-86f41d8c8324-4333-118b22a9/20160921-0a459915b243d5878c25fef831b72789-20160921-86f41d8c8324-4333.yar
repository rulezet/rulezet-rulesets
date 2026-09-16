rule _20160921_0a459915b243d5878c25fef831b72789_20160921_86f41d8c8324_4333 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_86f41d8c83240a68770674107f15f162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"

  strings:
    $s1 = "nction f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s2 = "return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})()," ascii
    $s3 = "Kl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s4 = "nction f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s5 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}