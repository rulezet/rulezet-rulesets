rule TTP_XOR_QUAD_CurrentVersionRun_d6d6 {
  strings:
    $key_d6d6 = { 85 b9 [2] a1 b7 [2] 8a 9b [2] a4 b9 [2] b0 a2 [2] bf b8 [2] a1 a5 [2] a3 a4 [2] b8 a2 [2] a4 a5 [2] b8 8a }

  condition:
    any of them
}