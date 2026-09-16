rule TTP_XOR_QUAD_CurrentVersionRun_bc76 {
  strings:
    $key_bc76 = { ef 19 [2] cb 17 [2] e0 3b [2] ce 19 [2] da 02 [2] d5 18 [2] cb 05 [2] c9 04 [2] d2 02 [2] ce 05 [2] d2 2a }

  condition:
    any of them
}