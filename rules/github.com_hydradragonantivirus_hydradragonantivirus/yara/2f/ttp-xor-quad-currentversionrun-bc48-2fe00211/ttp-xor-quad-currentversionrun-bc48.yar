rule TTP_XOR_QUAD_CurrentVersionRun_bc48 {
  strings:
    $key_bc48 = { ef 27 [2] cb 29 [2] e0 05 [2] ce 27 [2] da 3c [2] d5 26 [2] cb 3b [2] c9 3a [2] d2 3c [2] ce 3b [2] d2 14 }

  condition:
    any of them
}