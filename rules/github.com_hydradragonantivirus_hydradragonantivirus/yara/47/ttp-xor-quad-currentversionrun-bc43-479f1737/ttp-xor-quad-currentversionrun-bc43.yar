rule TTP_XOR_QUAD_CurrentVersionRun_bc43 {
  strings:
    $key_bc43 = { ef 2c [2] cb 22 [2] e0 0e [2] ce 2c [2] da 37 [2] d5 2d [2] cb 30 [2] c9 31 [2] d2 37 [2] ce 30 [2] d2 1f }

  condition:
    any of them
}