rule TTP_XOR_QUAD_CurrentVersionRun_c7c2 {
  strings:
    $key_c7c2 = { 94 ad [2] b0 a3 [2] 9b 8f [2] b5 ad [2] a1 b6 [2] ae ac [2] b0 b1 [2] b2 b0 [2] a9 b6 [2] b5 b1 [2] a9 9e }

  condition:
    any of them
}