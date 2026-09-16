rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_74aa1eb054c4_4730 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"
    hash3       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash4       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s2 = "urn \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(fu" ascii
    $s3 = "f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WI" ascii
    $s4 = "{return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s5 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}