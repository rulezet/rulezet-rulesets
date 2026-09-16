rule TTP_XOR_QUAD_CurrentVersionRun_0087 {
  strings:
    $key_0087 = { 53 e8 [2] 77 e6 [2] 5c ca [2] 72 e8 [2] 66 f3 [2] 69 e9 [2] 77 f4 [2] 75 f5 [2] 6e f3 [2] 72 f4 [2] 6e db }

  condition:
    any of them
}