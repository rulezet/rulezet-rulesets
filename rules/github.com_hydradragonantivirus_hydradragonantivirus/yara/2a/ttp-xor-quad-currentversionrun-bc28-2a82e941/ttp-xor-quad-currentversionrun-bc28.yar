rule TTP_XOR_QUAD_CurrentVersionRun_bc28 {
  strings:
    $key_bc28 = { ef 47 [2] cb 49 [2] e0 65 [2] ce 47 [2] da 5c [2] d5 46 [2] cb 5b [2] c9 5a [2] d2 5c [2] ce 5b [2] d2 74 }

  condition:
    any of them
}