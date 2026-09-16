rule TTP_XOR_QUAD_CurrentVersionRun_e7aa {
  strings:
    $key_e7aa = { b4 c5 [2] 90 cb [2] bb e7 [2] 95 c5 [2] 81 de [2] 8e c4 [2] 90 d9 [2] 92 d8 [2] 89 de [2] 95 d9 [2] 89 f6 }

  condition:
    any of them
}