rule TTP_XOR_QUAD_CurrentVersionRun_e7b9 {
  strings:
    $key_e7b9 = { b4 d6 [2] 90 d8 [2] bb f4 [2] 95 d6 [2] 81 cd [2] 8e d7 [2] 90 ca [2] 92 cb [2] 89 cd [2] 95 ca [2] 89 e5 }

  condition:
    any of them
}