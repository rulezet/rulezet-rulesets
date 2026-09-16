rule TTP_XOR_QUAD_CurrentVersionRun_ab15 {
  strings:
    $key_ab15 = { f8 7a [2] dc 74 [2] f7 58 [2] d9 7a [2] cd 61 [2] c2 7b [2] dc 66 [2] de 67 [2] c5 61 [2] d9 66 [2] c5 49 }

  condition:
    any of them
}