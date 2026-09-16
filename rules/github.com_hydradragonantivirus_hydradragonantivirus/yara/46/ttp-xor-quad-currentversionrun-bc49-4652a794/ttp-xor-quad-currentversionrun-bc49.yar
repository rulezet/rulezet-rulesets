rule TTP_XOR_QUAD_CurrentVersionRun_bc49 {
  strings:
    $key_bc49 = { ef 26 [2] cb 28 [2] e0 04 [2] ce 26 [2] da 3d [2] d5 27 [2] cb 3a [2] c9 3b [2] d2 3d [2] ce 3a [2] d2 15 }

  condition:
    any of them
}