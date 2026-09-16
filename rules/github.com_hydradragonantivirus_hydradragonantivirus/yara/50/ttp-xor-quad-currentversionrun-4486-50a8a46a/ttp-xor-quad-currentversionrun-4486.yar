rule TTP_XOR_QUAD_CurrentVersionRun_4486 {
  strings:
    $key_4486 = { 17 e9 [2] 33 e7 [2] 18 cb [2] 36 e9 [2] 22 f2 [2] 2d e8 [2] 33 f5 [2] 31 f4 [2] 2a f2 [2] 36 f5 [2] 2a da }

  condition:
    any of them
}