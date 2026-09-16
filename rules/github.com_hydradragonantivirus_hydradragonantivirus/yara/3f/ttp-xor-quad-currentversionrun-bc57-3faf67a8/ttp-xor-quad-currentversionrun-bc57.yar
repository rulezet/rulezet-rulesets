rule TTP_XOR_QUAD_CurrentVersionRun_bc57 {
  strings:
    $key_bc57 = { ef 38 [2] cb 36 [2] e0 1a [2] ce 38 [2] da 23 [2] d5 39 [2] cb 24 [2] c9 25 [2] d2 23 [2] ce 24 [2] d2 0b }

  condition:
    any of them
}