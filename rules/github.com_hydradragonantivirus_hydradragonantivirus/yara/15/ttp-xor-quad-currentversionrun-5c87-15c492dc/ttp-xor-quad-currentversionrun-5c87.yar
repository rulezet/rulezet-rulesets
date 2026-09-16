rule TTP_XOR_QUAD_CurrentVersionRun_5c87 {
  strings:
    $key_5c87 = { 0f e8 [2] 2b e6 [2] 00 ca [2] 2e e8 [2] 3a f3 [2] 35 e9 [2] 2b f4 [2] 29 f5 [2] 32 f3 [2] 2e f4 [2] 32 db }

  condition:
    any of them
}