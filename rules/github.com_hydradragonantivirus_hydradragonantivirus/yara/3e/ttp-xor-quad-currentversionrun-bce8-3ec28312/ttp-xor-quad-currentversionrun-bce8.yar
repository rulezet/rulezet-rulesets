rule TTP_XOR_QUAD_CurrentVersionRun_bce8 {
  strings:
    $key_bce8 = { ef 87 [2] cb 89 [2] e0 a5 [2] ce 87 [2] da 9c [2] d5 86 [2] cb 9b [2] c9 9a [2] d2 9c [2] ce 9b [2] d2 b4 }

  condition:
    any of them
}