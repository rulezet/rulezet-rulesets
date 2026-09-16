rule TTP_XOR_QUAD_CurrentVersionRun_bc3b {
  strings:
    $key_bc3b = { ef 54 [2] cb 5a [2] e0 76 [2] ce 54 [2] da 4f [2] d5 55 [2] cb 48 [2] c9 49 [2] d2 4f [2] ce 48 [2] d2 67 }

  condition:
    any of them
}