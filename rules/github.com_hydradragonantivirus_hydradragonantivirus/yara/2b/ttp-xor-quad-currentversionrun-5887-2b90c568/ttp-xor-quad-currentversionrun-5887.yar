rule TTP_XOR_QUAD_CurrentVersionRun_5887 {
  strings:
    $key_5887 = { 0b e8 [2] 2f e6 [2] 04 ca [2] 2a e8 [2] 3e f3 [2] 31 e9 [2] 2f f4 [2] 2d f5 [2] 36 f3 [2] 2a f4 [2] 36 db }

  condition:
    any of them
}