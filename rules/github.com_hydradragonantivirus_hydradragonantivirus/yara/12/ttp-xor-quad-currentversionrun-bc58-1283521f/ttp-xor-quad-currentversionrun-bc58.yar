rule TTP_XOR_QUAD_CurrentVersionRun_bc58 {
  strings:
    $key_bc58 = { ef 37 [2] cb 39 [2] e0 15 [2] ce 37 [2] da 2c [2] d5 36 [2] cb 2b [2] c9 2a [2] d2 2c [2] ce 2b [2] d2 04 }

  condition:
    any of them
}