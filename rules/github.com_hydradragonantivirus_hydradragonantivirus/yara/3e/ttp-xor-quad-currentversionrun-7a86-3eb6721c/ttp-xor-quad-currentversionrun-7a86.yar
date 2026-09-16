rule TTP_XOR_QUAD_CurrentVersionRun_7a86 {
  strings:
    $key_7a86 = { 29 e9 [2] 0d e7 [2] 26 cb [2] 08 e9 [2] 1c f2 [2] 13 e8 [2] 0d f5 [2] 0f f4 [2] 14 f2 [2] 08 f5 [2] 14 da }

  condition:
    any of them
}