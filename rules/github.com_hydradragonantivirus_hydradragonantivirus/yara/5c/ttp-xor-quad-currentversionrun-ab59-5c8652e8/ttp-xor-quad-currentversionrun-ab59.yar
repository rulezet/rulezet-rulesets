rule TTP_XOR_QUAD_CurrentVersionRun_ab59 {
  strings:
    $key_ab59 = { f8 36 [2] dc 38 [2] f7 14 [2] d9 36 [2] cd 2d [2] c2 37 [2] dc 2a [2] de 2b [2] c5 2d [2] d9 2a [2] c5 05 }

  condition:
    any of them
}