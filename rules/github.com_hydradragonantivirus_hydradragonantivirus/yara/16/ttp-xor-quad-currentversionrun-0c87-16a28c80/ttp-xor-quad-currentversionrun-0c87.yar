rule TTP_XOR_QUAD_CurrentVersionRun_0c87 {
  strings:
    $key_0c87 = { 5f e8 [2] 7b e6 [2] 50 ca [2] 7e e8 [2] 6a f3 [2] 65 e9 [2] 7b f4 [2] 79 f5 [2] 62 f3 [2] 7e f4 [2] 62 db }

  condition:
    any of them
}