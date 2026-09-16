rule TTP_XOR_QUAD_CurrentVersionRun_ab5b {
  strings:
    $key_ab5b = { f8 34 [2] dc 3a [2] f7 16 [2] d9 34 [2] cd 2f [2] c2 35 [2] dc 28 [2] de 29 [2] c5 2f [2] d9 28 [2] c5 07 }

  condition:
    any of them
}