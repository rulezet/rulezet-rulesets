rule TTP_XOR_QUAD_CurrentVersionRun_ab72 {
  strings:
    $key_ab72 = { f8 1d [2] dc 13 [2] f7 3f [2] d9 1d [2] cd 06 [2] c2 1c [2] dc 01 [2] de 00 [2] c5 06 [2] d9 01 [2] c5 2e }

  condition:
    any of them
}