rule TTP_XOR_QUAD_CurrentVersionRun_5886 {
  strings:
    $key_5886 = { 0b e9 [2] 2f e7 [2] 04 cb [2] 2a e9 [2] 3e f2 [2] 31 e8 [2] 2f f5 [2] 2d f4 [2] 36 f2 [2] 2a f5 [2] 36 da }

  condition:
    any of them
}