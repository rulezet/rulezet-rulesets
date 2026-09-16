rule TTP_XOR_QUAD_CurrentVersionRun_6486 {
  strings:
    $key_6486 = { 37 e9 [2] 13 e7 [2] 38 cb [2] 16 e9 [2] 02 f2 [2] 0d e8 [2] 13 f5 [2] 11 f4 [2] 0a f2 [2] 16 f5 [2] 0a da }

  condition:
    any of them
}