rule TTP_XOR_QUAD_CurrentVersionRun_bcf1 {
  strings:
    $key_bcf1 = { ef 9e [2] cb 90 [2] e0 bc [2] ce 9e [2] da 85 [2] d5 9f [2] cb 82 [2] c9 83 [2] d2 85 [2] ce 82 [2] d2 ad }

  condition:
    any of them
}