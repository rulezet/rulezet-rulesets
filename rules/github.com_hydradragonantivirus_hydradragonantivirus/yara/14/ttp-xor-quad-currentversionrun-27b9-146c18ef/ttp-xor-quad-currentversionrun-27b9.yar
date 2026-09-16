rule TTP_XOR_QUAD_CurrentVersionRun_27b9 {
  strings:
    $key_27b9 = { 74 d6 [2] 50 d8 [2] 7b f4 [2] 55 d6 [2] 41 cd [2] 4e d7 [2] 50 ca [2] 52 cb [2] 49 cd [2] 55 ca [2] 49 e5 }

  condition:
    any of them
}