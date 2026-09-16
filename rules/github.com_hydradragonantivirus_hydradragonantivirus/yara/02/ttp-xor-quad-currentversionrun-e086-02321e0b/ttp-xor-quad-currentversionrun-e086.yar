rule TTP_XOR_QUAD_CurrentVersionRun_e086 {
  strings:
    $key_e086 = { b3 e9 [2] 97 e7 [2] bc cb [2] 92 e9 [2] 86 f2 [2] 89 e8 [2] 97 f5 [2] 95 f4 [2] 8e f2 [2] 92 f5 [2] 8e da }

  condition:
    any of them
}