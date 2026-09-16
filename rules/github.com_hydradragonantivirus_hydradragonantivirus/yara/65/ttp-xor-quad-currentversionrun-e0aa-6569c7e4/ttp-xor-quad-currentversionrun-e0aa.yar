rule TTP_XOR_QUAD_CurrentVersionRun_e0aa {
  strings:
    $key_e0aa = { b3 c5 [2] 97 cb [2] bc e7 [2] 92 c5 [2] 86 de [2] 89 c4 [2] 97 d9 [2] 95 d8 [2] 8e de [2] 92 d9 [2] 8e f6 }

  condition:
    any of them
}