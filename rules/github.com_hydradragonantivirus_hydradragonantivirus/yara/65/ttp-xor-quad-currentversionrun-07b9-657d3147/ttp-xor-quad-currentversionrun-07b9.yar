rule TTP_XOR_QUAD_CurrentVersionRun_07b9 {
  strings:
    $key_07b9 = { 54 d6 [2] 70 d8 [2] 5b f4 [2] 75 d6 [2] 61 cd [2] 6e d7 [2] 70 ca [2] 72 cb [2] 69 cd [2] 75 ca [2] 69 e5 }

  condition:
    any of them
}