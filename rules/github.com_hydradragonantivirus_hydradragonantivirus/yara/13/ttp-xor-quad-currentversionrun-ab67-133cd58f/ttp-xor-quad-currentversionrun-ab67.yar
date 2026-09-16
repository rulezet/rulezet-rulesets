rule TTP_XOR_QUAD_CurrentVersionRun_ab67 {
  strings:
    $key_ab67 = { f8 08 [2] dc 06 [2] f7 2a [2] d9 08 [2] cd 13 [2] c2 09 [2] dc 14 [2] de 15 [2] c5 13 [2] d9 14 [2] c5 3b }

  condition:
    any of them
}