rule TTP_XOR_QUAD_CurrentVersionRun_2e86 {
  strings:
    $key_2e86 = { 7d e9 [2] 59 e7 [2] 72 cb [2] 5c e9 [2] 48 f2 [2] 47 e8 [2] 59 f5 [2] 5b f4 [2] 40 f2 [2] 5c f5 [2] 40 da }

  condition:
    any of them
}