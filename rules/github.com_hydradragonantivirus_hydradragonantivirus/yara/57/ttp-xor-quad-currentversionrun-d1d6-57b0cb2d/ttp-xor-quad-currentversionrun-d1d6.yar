rule TTP_XOR_QUAD_CurrentVersionRun_d1d6 {
  strings:
    $key_d1d6 = { 82 b9 [2] a6 b7 [2] 8d 9b [2] a3 b9 [2] b7 a2 [2] b8 b8 [2] a6 a5 [2] a4 a4 [2] bf a2 [2] a3 a5 [2] bf 8a }

  condition:
    any of them
}