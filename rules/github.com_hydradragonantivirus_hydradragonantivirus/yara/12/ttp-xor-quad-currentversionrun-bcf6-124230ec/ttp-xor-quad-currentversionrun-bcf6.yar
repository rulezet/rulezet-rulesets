rule TTP_XOR_QUAD_CurrentVersionRun_bcf6 {
  strings:
    $key_bcf6 = { ef 99 [2] cb 97 [2] e0 bb [2] ce 99 [2] da 82 [2] d5 98 [2] cb 85 [2] c9 84 [2] d2 82 [2] ce 85 [2] d2 aa }

  condition:
    any of them
}