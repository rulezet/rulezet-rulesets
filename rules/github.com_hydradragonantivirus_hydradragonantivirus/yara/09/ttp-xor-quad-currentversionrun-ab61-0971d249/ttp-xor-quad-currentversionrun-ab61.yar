rule TTP_XOR_QUAD_CurrentVersionRun_ab61 {
  strings:
    $key_ab61 = { f8 0e [2] dc 00 [2] f7 2c [2] d9 0e [2] cd 15 [2] c2 0f [2] dc 12 [2] de 13 [2] c5 15 [2] d9 12 [2] c5 3d }

  condition:
    any of them
}