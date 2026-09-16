rule TTP_XOR_QUAD_CurrentVersionRun_ab37 {
  strings:
    $key_ab37 = { f8 58 [2] dc 56 [2] f7 7a [2] d9 58 [2] cd 43 [2] c2 59 [2] dc 44 [2] de 45 [2] c5 43 [2] d9 44 [2] c5 6b }

  condition:
    any of them
}