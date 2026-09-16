rule TTP_XOR_QUAD_CurrentVersionRun_a561 {
  strings:
    $key_a561 = { f6 0e [2] d2 00 [2] f9 2c [2] d7 0e [2] c3 15 [2] cc 0f [2] d2 12 [2] d0 13 [2] cb 15 [2] d7 12 [2] cb 3d }

  condition:
    any of them
}