rule TTP_XOR_QUAD_CurrentVersionRun_bcf7 {
  strings:
    $key_bcf7 = { ef 98 [2] cb 96 [2] e0 ba [2] ce 98 [2] da 83 [2] d5 99 [2] cb 84 [2] c9 85 [2] d2 83 [2] ce 84 [2] d2 ab }

  condition:
    any of them
}