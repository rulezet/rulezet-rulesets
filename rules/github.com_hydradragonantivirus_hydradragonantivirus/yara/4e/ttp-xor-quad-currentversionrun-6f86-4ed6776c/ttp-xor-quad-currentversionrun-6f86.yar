rule TTP_XOR_QUAD_CurrentVersionRun_6f86 {
  strings:
    $key_6f86 = { 3c e9 [2] 18 e7 [2] 33 cb [2] 1d e9 [2] 09 f2 [2] 06 e8 [2] 18 f5 [2] 1a f4 [2] 01 f2 [2] 1d f5 [2] 01 da }

  condition:
    any of them
}