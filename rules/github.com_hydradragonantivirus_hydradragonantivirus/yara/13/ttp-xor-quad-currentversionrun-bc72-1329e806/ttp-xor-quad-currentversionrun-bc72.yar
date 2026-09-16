rule TTP_XOR_QUAD_CurrentVersionRun_bc72 {
  strings:
    $key_bc72 = { ef 1d [2] cb 13 [2] e0 3f [2] ce 1d [2] da 06 [2] d5 1c [2] cb 01 [2] c9 00 [2] d2 06 [2] ce 01 [2] d2 2e }

  condition:
    any of them
}