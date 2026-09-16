rule TTP_XOR_QUAD_CurrentVersionRun_bc04 {
  strings:
    $key_bc04 = { ef 6b [2] cb 65 [2] e0 49 [2] ce 6b [2] da 70 [2] d5 6a [2] cb 77 [2] c9 76 [2] d2 70 [2] ce 77 [2] d2 58 }

  condition:
    any of them
}