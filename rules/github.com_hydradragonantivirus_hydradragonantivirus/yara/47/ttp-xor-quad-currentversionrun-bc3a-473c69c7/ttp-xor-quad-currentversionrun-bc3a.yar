rule TTP_XOR_QUAD_CurrentVersionRun_bc3a {
  strings:
    $key_bc3a = { ef 55 [2] cb 5b [2] e0 77 [2] ce 55 [2] da 4e [2] d5 54 [2] cb 49 [2] c9 48 [2] d2 4e [2] ce 49 [2] d2 66 }

  condition:
    any of them
}