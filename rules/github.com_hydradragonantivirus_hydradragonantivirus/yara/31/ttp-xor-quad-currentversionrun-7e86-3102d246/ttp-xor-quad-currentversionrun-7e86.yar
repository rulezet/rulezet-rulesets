rule TTP_XOR_QUAD_CurrentVersionRun_7e86 {
  strings:
    $key_7e86 = { 2d e9 [2] 09 e7 [2] 22 cb [2] 0c e9 [2] 18 f2 [2] 17 e8 [2] 09 f5 [2] 0b f4 [2] 10 f2 [2] 0c f5 [2] 10 da }

  condition:
    any of them
}