rule TTP_XOR_QUAD_CurrentVersionRun_ecb2 {
  strings:
    $key_ecb2 = { bf dd [2] 9b d3 [2] b0 ff [2] 9e dd [2] 8a c6 [2] 85 dc [2] 9b c1 [2] 99 c0 [2] 82 c6 [2] 9e c1 [2] 82 ee }

  condition:
    any of them
}