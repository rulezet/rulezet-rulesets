rule TTP_XOR_QUAD_CurrentVersionRun_ab56 {
  strings:
    $key_ab56 = { f8 39 [2] dc 37 [2] f7 1b [2] d9 39 [2] cd 22 [2] c2 38 [2] dc 25 [2] de 24 [2] c5 22 [2] d9 25 [2] c5 0a }

  condition:
    any of them
}