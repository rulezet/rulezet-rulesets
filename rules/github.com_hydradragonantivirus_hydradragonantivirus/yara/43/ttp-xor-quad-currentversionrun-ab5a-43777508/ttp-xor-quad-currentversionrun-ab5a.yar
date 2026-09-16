rule TTP_XOR_QUAD_CurrentVersionRun_ab5a {
  strings:
    $key_ab5a = { f8 35 [2] dc 3b [2] f7 17 [2] d9 35 [2] cd 2e [2] c2 34 [2] dc 29 [2] de 28 [2] c5 2e [2] d9 29 [2] c5 06 }

  condition:
    any of them
}