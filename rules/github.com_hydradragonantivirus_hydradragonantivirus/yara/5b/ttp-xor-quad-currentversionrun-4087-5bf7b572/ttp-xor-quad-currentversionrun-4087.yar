rule TTP_XOR_QUAD_CurrentVersionRun_4087 {
  strings:
    $key_4087 = { 13 e8 [2] 37 e6 [2] 1c ca [2] 32 e8 [2] 26 f3 [2] 29 e9 [2] 37 f4 [2] 35 f5 [2] 2e f3 [2] 32 f4 [2] 2e db }

  condition:
    any of them
}