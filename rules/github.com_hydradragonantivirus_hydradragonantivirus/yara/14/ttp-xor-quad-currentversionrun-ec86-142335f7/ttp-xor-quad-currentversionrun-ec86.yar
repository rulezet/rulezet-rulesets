rule TTP_XOR_QUAD_CurrentVersionRun_ec86 {
  strings:
    $key_ec86 = { bf e9 [2] 9b e7 [2] b0 cb [2] 9e e9 [2] 8a f2 [2] 85 e8 [2] 9b f5 [2] 99 f4 [2] 82 f2 [2] 9e f5 [2] 82 da }

  condition:
    any of them
}