rule TTP_XOR_QUAD_CurrentVersionRun_fa87 {
  strings:
    $key_fa87 = { a9 e8 [2] 8d e6 [2] a6 ca [2] 88 e8 [2] 9c f3 [2] 93 e9 [2] 8d f4 [2] 8f f5 [2] 94 f3 [2] 88 f4 [2] 94 db }

  condition:
    any of them
}