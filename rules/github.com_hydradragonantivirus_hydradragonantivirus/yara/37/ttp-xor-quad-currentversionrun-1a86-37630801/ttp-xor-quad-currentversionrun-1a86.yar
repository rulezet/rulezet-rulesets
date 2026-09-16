rule TTP_XOR_QUAD_CurrentVersionRun_1a86 {
  strings:
    $key_1a86 = { 49 e9 [2] 6d e7 [2] 46 cb [2] 68 e9 [2] 7c f2 [2] 73 e8 [2] 6d f5 [2] 6f f4 [2] 74 f2 [2] 68 f5 [2] 74 da }

  condition:
    any of them
}