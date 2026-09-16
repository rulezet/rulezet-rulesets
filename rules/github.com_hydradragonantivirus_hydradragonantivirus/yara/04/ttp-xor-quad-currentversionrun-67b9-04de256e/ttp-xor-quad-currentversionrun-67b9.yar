rule TTP_XOR_QUAD_CurrentVersionRun_67b9 {
  strings:
    $key_67b9 = { 34 d6 [2] 10 d8 [2] 3b f4 [2] 15 d6 [2] 01 cd [2] 0e d7 [2] 10 ca [2] 12 cb [2] 09 cd [2] 15 ca [2] 09 e5 }

  condition:
    any of them
}