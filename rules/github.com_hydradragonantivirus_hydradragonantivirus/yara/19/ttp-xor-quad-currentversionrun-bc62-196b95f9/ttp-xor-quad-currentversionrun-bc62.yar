rule TTP_XOR_QUAD_CurrentVersionRun_bc62 {
  strings:
    $key_bc62 = { ef 0d [2] cb 03 [2] e0 2f [2] ce 0d [2] da 16 [2] d5 0c [2] cb 11 [2] c9 10 [2] d2 16 [2] ce 11 [2] d2 3e }

  condition:
    any of them
}