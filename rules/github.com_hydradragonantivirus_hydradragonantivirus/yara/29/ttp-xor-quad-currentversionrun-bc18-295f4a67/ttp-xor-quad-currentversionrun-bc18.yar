rule TTP_XOR_QUAD_CurrentVersionRun_bc18 {
  strings:
    $key_bc18 = { ef 77 [2] cb 79 [2] e0 55 [2] ce 77 [2] da 6c [2] d5 76 [2] cb 6b [2] c9 6a [2] d2 6c [2] ce 6b [2] d2 44 }

  condition:
    any of them
}