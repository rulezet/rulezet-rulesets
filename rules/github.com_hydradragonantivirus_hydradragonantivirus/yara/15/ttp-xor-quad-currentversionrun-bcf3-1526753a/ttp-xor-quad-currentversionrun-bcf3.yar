rule TTP_XOR_QUAD_CurrentVersionRun_bcf3 {
  strings:
    $key_bcf3 = { ef 9c [2] cb 92 [2] e0 be [2] ce 9c [2] da 87 [2] d5 9d [2] cb 80 [2] c9 81 [2] d2 87 [2] ce 80 [2] d2 af }

  condition:
    any of them
}