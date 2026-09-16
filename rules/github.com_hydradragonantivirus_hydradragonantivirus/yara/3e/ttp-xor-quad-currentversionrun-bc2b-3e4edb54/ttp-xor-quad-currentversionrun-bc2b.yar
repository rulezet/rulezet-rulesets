rule TTP_XOR_QUAD_CurrentVersionRun_bc2b {
  strings:
    $key_bc2b = { ef 44 [2] cb 4a [2] e0 66 [2] ce 44 [2] da 5f [2] d5 45 [2] cb 58 [2] c9 59 [2] d2 5f [2] ce 58 [2] d2 77 }

  condition:
    any of them
}