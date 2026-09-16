rule TTP_XOR_QUAD_CurrentVersionRun_7087 {
  strings:
    $key_7087 = { 23 e8 [2] 07 e6 [2] 2c ca [2] 02 e8 [2] 16 f3 [2] 19 e9 [2] 07 f4 [2] 05 f5 [2] 1e f3 [2] 02 f4 [2] 1e db }

  condition:
    any of them
}