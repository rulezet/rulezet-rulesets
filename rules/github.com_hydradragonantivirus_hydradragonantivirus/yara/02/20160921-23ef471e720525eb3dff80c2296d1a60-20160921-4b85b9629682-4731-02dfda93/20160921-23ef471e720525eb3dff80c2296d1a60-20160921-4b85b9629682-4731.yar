rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_4b85b9629682_4731 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash3       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash4       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"

  strings:
    $s1 = "\"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(funct" ascii
    $s2 = "return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})()" ascii
    $s3 = "\"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(functi" ascii
    $s4 = " \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(func" ascii
    $s5 = "000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}