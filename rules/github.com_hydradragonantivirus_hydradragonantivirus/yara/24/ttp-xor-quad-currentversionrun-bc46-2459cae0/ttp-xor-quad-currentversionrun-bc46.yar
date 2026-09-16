rule TTP_XOR_QUAD_CurrentVersionRun_bc46 {
  strings:
    $key_bc46 = { ef 29 [2] cb 27 [2] e0 0b [2] ce 29 [2] da 32 [2] d5 28 [2] cb 35 [2] c9 34 [2] d2 32 [2] ce 35 [2] d2 1a }

  condition:
    any of them
}