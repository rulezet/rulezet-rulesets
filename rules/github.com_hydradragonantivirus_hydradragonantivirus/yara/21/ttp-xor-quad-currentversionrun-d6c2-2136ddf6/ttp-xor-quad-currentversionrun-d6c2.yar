rule TTP_XOR_QUAD_CurrentVersionRun_d6c2 {
  strings:
    $key_d6c2 = { 85 ad [2] a1 a3 [2] 8a 8f [2] a4 ad [2] b0 b6 [2] bf ac [2] a1 b1 [2] a3 b0 [2] b8 b6 [2] a4 b1 [2] b8 9e }

  condition:
    any of them
}