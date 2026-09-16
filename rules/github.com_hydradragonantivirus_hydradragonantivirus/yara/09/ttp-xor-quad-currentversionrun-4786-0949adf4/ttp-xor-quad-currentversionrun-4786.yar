rule TTP_XOR_QUAD_CurrentVersionRun_4786 {
  strings:
    $key_4786 = { 14 e9 [2] 30 e7 [2] 1b cb [2] 35 e9 [2] 21 f2 [2] 2e e8 [2] 30 f5 [2] 32 f4 [2] 29 f2 [2] 35 f5 [2] 29 da }

  condition:
    any of them
}