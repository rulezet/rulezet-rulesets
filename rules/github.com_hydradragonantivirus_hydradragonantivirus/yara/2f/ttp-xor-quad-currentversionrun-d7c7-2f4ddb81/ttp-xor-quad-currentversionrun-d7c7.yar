rule TTP_XOR_QUAD_CurrentVersionRun_d7c7 {
  strings:
    $key_d7c7 = { 84 a8 [2] a0 a6 [2] 8b 8a [2] a5 a8 [2] b1 b3 [2] be a9 [2] a0 b4 [2] a2 b5 [2] b9 b3 [2] a5 b4 [2] b9 9b }

  condition:
    any of them
}