rule TTP_XOR_QUAD_CurrentVersionRun_bc77 {
  strings:
    $key_bc77 = { ef 18 [2] cb 16 [2] e0 3a [2] ce 18 [2] da 03 [2] d5 19 [2] cb 04 [2] c9 05 [2] d2 03 [2] ce 04 [2] d2 2b }

  condition:
    any of them
}