rule TTP_XOR_QUAD_CurrentVersionRun_ab5e {
  strings:
    $key_ab5e = { f8 31 [2] dc 3f [2] f7 13 [2] d9 31 [2] cd 2a [2] c2 30 [2] dc 2d [2] de 2c [2] c5 2a [2] d9 2d [2] c5 02 }

  condition:
    any of them
}