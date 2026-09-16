rule TTP_XOR_QUAD_CurrentVersionRun_1087 {
  strings:
    $key_1087 = { 43 e8 [2] 67 e6 [2] 4c ca [2] 62 e8 [2] 76 f3 [2] 79 e9 [2] 67 f4 [2] 65 f5 [2] 7e f3 [2] 62 f4 [2] 7e db }

  condition:
    any of them
}