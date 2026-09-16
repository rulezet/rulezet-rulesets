rule TTP_XOR_QUAD_CurrentVersionRun_5987 {
  strings:
    $key_5987 = { 0a e8 [2] 2e e6 [2] 05 ca [2] 2b e8 [2] 3f f3 [2] 30 e9 [2] 2e f4 [2] 2c f5 [2] 37 f3 [2] 2b f4 [2] 37 db }

  condition:
    any of them
}