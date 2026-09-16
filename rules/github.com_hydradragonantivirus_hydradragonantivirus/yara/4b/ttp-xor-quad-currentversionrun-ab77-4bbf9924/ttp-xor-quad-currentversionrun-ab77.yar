rule TTP_XOR_QUAD_CurrentVersionRun_ab77 {
  strings:
    $key_ab77 = { f8 18 [2] dc 16 [2] f7 3a [2] d9 18 [2] cd 03 [2] c2 19 [2] dc 04 [2] de 05 [2] c5 03 [2] d9 04 [2] c5 2b }

  condition:
    any of them
}