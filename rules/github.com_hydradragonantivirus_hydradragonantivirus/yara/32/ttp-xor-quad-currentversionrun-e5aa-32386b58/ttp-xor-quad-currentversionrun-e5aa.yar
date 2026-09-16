rule TTP_XOR_QUAD_CurrentVersionRun_e5aa {
  strings:
    $key_e5aa = { b6 c5 [2] 92 cb [2] b9 e7 [2] 97 c5 [2] 83 de [2] 8c c4 [2] 92 d9 [2] 90 d8 [2] 8b de [2] 97 d9 [2] 8b f6 }

  condition:
    any of them
}