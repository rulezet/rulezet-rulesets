rule TTP_XOR_QUAD_CurrentVersionRun_bc15 {
  strings:
    $key_bc15 = { ef 7a [2] cb 74 [2] e0 58 [2] ce 7a [2] da 61 [2] d5 7b [2] cb 66 [2] c9 67 [2] d2 61 [2] ce 66 [2] d2 49 }

  condition:
    any of them
}