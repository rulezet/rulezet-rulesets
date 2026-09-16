rule TTP_XOR_QUAD_CurrentVersionRun_ab43 {
  strings:
    $key_ab43 = { f8 2c [2] dc 22 [2] f7 0e [2] d9 2c [2] cd 37 [2] c2 2d [2] dc 30 [2] de 31 [2] c5 37 [2] d9 30 [2] c5 1f }

  condition:
    any of them
}