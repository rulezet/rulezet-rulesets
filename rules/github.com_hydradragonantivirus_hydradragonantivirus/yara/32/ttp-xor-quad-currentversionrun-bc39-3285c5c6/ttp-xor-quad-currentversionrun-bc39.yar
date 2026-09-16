rule TTP_XOR_QUAD_CurrentVersionRun_bc39 {
  strings:
    $key_bc39 = { ef 56 [2] cb 58 [2] e0 74 [2] ce 56 [2] da 4d [2] d5 57 [2] cb 4a [2] c9 4b [2] d2 4d [2] ce 4a [2] d2 65 }

  condition:
    any of them
}