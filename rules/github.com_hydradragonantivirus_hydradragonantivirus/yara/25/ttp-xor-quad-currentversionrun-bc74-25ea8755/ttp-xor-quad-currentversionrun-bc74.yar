rule TTP_XOR_QUAD_CurrentVersionRun_bc74 {
  strings:
    $key_bc74 = { ef 1b [2] cb 15 [2] e0 39 [2] ce 1b [2] da 00 [2] d5 1a [2] cb 07 [2] c9 06 [2] d2 00 [2] ce 07 [2] d2 28 }

  condition:
    any of them
}