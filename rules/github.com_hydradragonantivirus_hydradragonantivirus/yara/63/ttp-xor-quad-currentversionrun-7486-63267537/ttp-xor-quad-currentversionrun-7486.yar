rule TTP_XOR_QUAD_CurrentVersionRun_7486 {
  strings:
    $key_7486 = { 27 e9 [2] 03 e7 [2] 28 cb [2] 06 e9 [2] 12 f2 [2] 1d e8 [2] 03 f5 [2] 01 f4 [2] 1a f2 [2] 06 f5 [2] 1a da }

  condition:
    any of them
}