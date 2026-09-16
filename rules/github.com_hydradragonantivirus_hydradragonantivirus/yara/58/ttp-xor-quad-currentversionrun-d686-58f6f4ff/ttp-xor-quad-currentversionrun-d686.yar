rule TTP_XOR_QUAD_CurrentVersionRun_d686 {
  strings:
    $key_d686 = { 85 e9 [2] a1 e7 [2] 8a cb [2] a4 e9 [2] b0 f2 [2] bf e8 [2] a1 f5 [2] a3 f4 [2] b8 f2 [2] a4 f5 [2] b8 da }

  condition:
    any of them
}