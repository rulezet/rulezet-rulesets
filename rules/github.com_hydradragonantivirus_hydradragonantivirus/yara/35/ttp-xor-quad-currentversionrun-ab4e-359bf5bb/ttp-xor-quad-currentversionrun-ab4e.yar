rule TTP_XOR_QUAD_CurrentVersionRun_ab4e {
  strings:
    $key_ab4e = { f8 21 [2] dc 2f [2] f7 03 [2] d9 21 [2] cd 3a [2] c2 20 [2] dc 3d [2] de 3c [2] c5 3a [2] d9 3d [2] c5 12 }

  condition:
    any of them
}