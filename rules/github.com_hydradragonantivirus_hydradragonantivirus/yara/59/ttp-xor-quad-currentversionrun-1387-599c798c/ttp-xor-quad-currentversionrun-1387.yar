rule TTP_XOR_QUAD_CurrentVersionRun_1387 {
  strings:
    $key_1387 = { 40 e8 [2] 64 e6 [2] 4f ca [2] 61 e8 [2] 75 f3 [2] 7a e9 [2] 64 f4 [2] 66 f5 [2] 7d f3 [2] 61 f4 [2] 7d db }

  condition:
    any of them
}