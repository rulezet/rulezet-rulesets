rule TTP_XOR_QUAD_CurrentVersionRun_bc5b {
  strings:
    $key_bc5b = { ef 34 [2] cb 3a [2] e0 16 [2] ce 34 [2] da 2f [2] d5 35 [2] cb 28 [2] c9 29 [2] d2 2f [2] ce 28 [2] d2 07 }

  condition:
    any of them
}