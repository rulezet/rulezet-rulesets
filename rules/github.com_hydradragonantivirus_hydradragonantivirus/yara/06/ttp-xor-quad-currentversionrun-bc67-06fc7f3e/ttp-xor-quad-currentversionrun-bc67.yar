rule TTP_XOR_QUAD_CurrentVersionRun_bc67 {
  strings:
    $key_bc67 = { ef 08 [2] cb 06 [2] e0 2a [2] ce 08 [2] da 13 [2] d5 09 [2] cb 14 [2] c9 15 [2] d2 13 [2] ce 14 [2] d2 3b }

  condition:
    any of them
}