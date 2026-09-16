rule TTP_XOR_QUAD_CurrentVersionRun_7886 {
  strings:
    $key_7886 = { 2b e9 [2] 0f e7 [2] 24 cb [2] 0a e9 [2] 1e f2 [2] 11 e8 [2] 0f f5 [2] 0d f4 [2] 16 f2 [2] 0a f5 [2] 16 da }

  condition:
    any of them
}