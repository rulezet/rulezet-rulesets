rule TTP_XOR_QUAD_CurrentVersionRun_bc27 {
  strings:
    $key_bc27 = { ef 48 [2] cb 46 [2] e0 6a [2] ce 48 [2] da 53 [2] d5 49 [2] cb 54 [2] c9 55 [2] d2 53 [2] ce 54 [2] d2 7b }

  condition:
    any of them
}