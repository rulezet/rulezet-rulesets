rule TTP_XOR_QUAD_CurrentVersionRun_ab1b {
  strings:
    $key_ab1b = { f8 74 [2] dc 7a [2] f7 56 [2] d9 74 [2] cd 6f [2] c2 75 [2] dc 68 [2] de 69 [2] c5 6f [2] d9 68 [2] c5 47 }

  condition:
    any of them
}