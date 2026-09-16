rule TTP_XOR_QUAD_CurrentVersionRun_bc56 {
  strings:
    $key_bc56 = { ef 39 [2] cb 37 [2] e0 1b [2] ce 39 [2] da 22 [2] d5 38 [2] cb 25 [2] c9 24 [2] d2 22 [2] ce 25 [2] d2 0a }

  condition:
    any of them
}