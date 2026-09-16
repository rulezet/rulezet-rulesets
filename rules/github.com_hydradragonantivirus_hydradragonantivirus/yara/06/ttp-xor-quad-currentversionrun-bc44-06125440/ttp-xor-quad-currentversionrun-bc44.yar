rule TTP_XOR_QUAD_CurrentVersionRun_bc44 {
  strings:
    $key_bc44 = { ef 2b [2] cb 25 [2] e0 09 [2] ce 2b [2] da 30 [2] d5 2a [2] cb 37 [2] c9 36 [2] d2 30 [2] ce 37 [2] d2 18 }

  condition:
    any of them
}