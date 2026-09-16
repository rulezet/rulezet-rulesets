rule TTP_XOR_QUAD_CurrentVersionRun_bc1a {
  strings:
    $key_bc1a = { ef 75 [2] cb 7b [2] e0 57 [2] ce 75 [2] da 6e [2] d5 74 [2] cb 69 [2] c9 68 [2] d2 6e [2] ce 69 [2] d2 46 }

  condition:
    any of them
}