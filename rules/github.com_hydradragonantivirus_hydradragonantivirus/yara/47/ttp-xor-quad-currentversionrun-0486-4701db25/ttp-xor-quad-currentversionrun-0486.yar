rule TTP_XOR_QUAD_CurrentVersionRun_0486 {
  strings:
    $key_0486 = { 57 e9 [2] 73 e7 [2] 58 cb [2] 76 e9 [2] 62 f2 [2] 6d e8 [2] 73 f5 [2] 71 f4 [2] 6a f2 [2] 76 f5 [2] 6a da }

  condition:
    any of them
}