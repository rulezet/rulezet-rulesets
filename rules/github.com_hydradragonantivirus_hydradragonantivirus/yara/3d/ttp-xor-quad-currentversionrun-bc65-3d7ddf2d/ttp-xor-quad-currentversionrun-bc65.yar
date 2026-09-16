rule TTP_XOR_QUAD_CurrentVersionRun_bc65 {
  strings:
    $key_bc65 = { ef 0a [2] cb 04 [2] e0 28 [2] ce 0a [2] da 11 [2] d5 0b [2] cb 16 [2] c9 17 [2] d2 11 [2] ce 16 [2] d2 39 }

  condition:
    any of them
}