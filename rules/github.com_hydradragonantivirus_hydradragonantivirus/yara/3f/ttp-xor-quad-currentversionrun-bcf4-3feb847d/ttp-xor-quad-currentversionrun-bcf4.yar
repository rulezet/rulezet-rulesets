rule TTP_XOR_QUAD_CurrentVersionRun_bcf4 {
  strings:
    $key_bcf4 = { ef 9b [2] cb 95 [2] e0 b9 [2] ce 9b [2] da 80 [2] d5 9a [2] cb 87 [2] c9 86 [2] d2 80 [2] ce 87 [2] d2 a8 }

  condition:
    any of them
}