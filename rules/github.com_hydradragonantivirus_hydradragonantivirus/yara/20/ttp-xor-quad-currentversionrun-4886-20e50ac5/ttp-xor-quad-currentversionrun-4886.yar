rule TTP_XOR_QUAD_CurrentVersionRun_4886 {
  strings:
    $key_4886 = { 1b e9 [2] 3f e7 [2] 14 cb [2] 3a e9 [2] 2e f2 [2] 21 e8 [2] 3f f5 [2] 3d f4 [2] 26 f2 [2] 3a f5 [2] 26 da }

  condition:
    any of them
}