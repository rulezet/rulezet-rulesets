rule TTP_XOR_QUAD_CurrentVersionRun_10b9 {
  strings:
    $key_10b9 = { 43 d6 [2] 67 d8 [2] 4c f4 [2] 62 d6 [2] 76 cd [2] 79 d7 [2] 67 ca [2] 65 cb [2] 7e cd [2] 62 ca [2] 7e e5 }

  condition:
    any of them
}