rule _20160921_8b27f7688489936aa1cc7fded52f4a64_20160921_c1184914bc80_3084 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash2       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s2 = "urn \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3 = "000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa" ascii
    $s4 = "nction f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii
    $s5 = "urn \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s6 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DNa\";})(),(function f000(" ascii
    $s7 = "Jm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}