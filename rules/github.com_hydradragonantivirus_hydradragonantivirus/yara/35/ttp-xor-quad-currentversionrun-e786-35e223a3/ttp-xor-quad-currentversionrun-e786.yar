rule TTP_XOR_QUAD_CurrentVersionRun_e786 {
  strings:
    $key_e786 = { b4 e9 [2] 90 e7 [2] bb cb [2] 95 e9 [2] 81 f2 [2] 8e e8 [2] 90 f5 [2] 92 f4 [2] 89 f2 [2] 95 f5 [2] 89 da }

  condition:
    any of them
}