rule TTP_XOR_QUAD_CurrentVersionRun_d187 {
  strings:
    $key_d187 = { 82 e8 [2] a6 e6 [2] 8d ca [2] a3 e8 [2] b7 f3 [2] b8 e9 [2] a6 f4 [2] a4 f5 [2] bf f3 [2] a3 f4 [2] bf db }

  condition:
    any of them
}