rule TTP_XOR_QUAD_CurrentVersionRun_3f86 {
  strings:
    $key_3f86 = { 6c e9 [2] 48 e7 [2] 63 cb [2] 4d e9 [2] 59 f2 [2] 56 e8 [2] 48 f5 [2] 4a f4 [2] 51 f2 [2] 4d f5 [2] 51 da }

  condition:
    any of them
}