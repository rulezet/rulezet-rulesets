rule TTP_XOR_QUAD_CurrentVersionRun_bc78 {
  strings:
    $key_bc78 = { ef 17 [2] cb 19 [2] e0 35 [2] ce 17 [2] da 0c [2] d5 16 [2] cb 0b [2] c9 0a [2] d2 0c [2] ce 0b [2] d2 24 }

  condition:
    any of them
}