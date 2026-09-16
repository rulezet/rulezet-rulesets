rule TTP_XOR_QUAD_CurrentVersionRun_bc19 {
  strings:
    $key_bc19 = { ef 76 [2] cb 78 [2] e0 54 [2] ce 76 [2] da 6d [2] d5 77 [2] cb 6a [2] c9 6b [2] d2 6d [2] ce 6a [2] d2 45 }

  condition:
    any of them
}