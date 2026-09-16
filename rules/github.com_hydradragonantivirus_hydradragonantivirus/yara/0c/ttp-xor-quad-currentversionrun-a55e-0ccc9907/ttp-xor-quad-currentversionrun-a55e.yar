rule TTP_XOR_QUAD_CurrentVersionRun_a55e {
  strings:
    $key_a55e = { f6 31 [2] d2 3f [2] f9 13 [2] d7 31 [2] c3 2a [2] cc 30 [2] d2 2d [2] d0 2c [2] cb 2a [2] d7 2d [2] cb 02 }

  condition:
    any of them
}