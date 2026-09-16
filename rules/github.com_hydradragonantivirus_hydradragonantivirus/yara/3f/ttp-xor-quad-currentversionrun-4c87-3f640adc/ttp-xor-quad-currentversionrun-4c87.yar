rule TTP_XOR_QUAD_CurrentVersionRun_4c87 {
  strings:
    $key_4c87 = { 1f e8 [2] 3b e6 [2] 10 ca [2] 3e e8 [2] 2a f3 [2] 25 e9 [2] 3b f4 [2] 39 f5 [2] 22 f3 [2] 3e f4 [2] 22 db }

  condition:
    any of them
}