rule TTP_XOR_QUAD_CurrentVersionRun_ab5d {
  strings:
    $key_ab5d = { f8 32 [2] dc 3c [2] f7 10 [2] d9 32 [2] cd 29 [2] c2 33 [2] dc 2e [2] de 2f [2] c5 29 [2] d9 2e [2] c5 01 }

  condition:
    any of them
}