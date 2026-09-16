rule TTP_XOR_QUAD_CurrentVersionRun_a542 {
  strings:
    $key_a542 = { f6 2d [2] d2 23 [2] f9 0f [2] d7 2d [2] c3 36 [2] cc 2c [2] d2 31 [2] d0 30 [2] cb 36 [2] d7 31 [2] cb 1e }

  condition:
    any of them
}