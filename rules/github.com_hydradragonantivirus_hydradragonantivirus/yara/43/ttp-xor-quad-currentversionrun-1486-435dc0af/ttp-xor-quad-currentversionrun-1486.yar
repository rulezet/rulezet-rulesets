rule TTP_XOR_QUAD_CurrentVersionRun_1486 {
  strings:
    $key_1486 = { 47 e9 [2] 63 e7 [2] 48 cb [2] 66 e9 [2] 72 f2 [2] 7d e8 [2] 63 f5 [2] 61 f4 [2] 7a f2 [2] 66 f5 [2] 7a da }

  condition:
    any of them
}