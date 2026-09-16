rule TTP_XOR_QUAD_CurrentVersionRun_60b9 {
  strings:
    $key_60b9 = { 33 d6 [2] 17 d8 [2] 3c f4 [2] 12 d6 [2] 06 cd [2] 09 d7 [2] 17 ca [2] 15 cb [2] 0e cd [2] 12 ca [2] 0e e5 }

  condition:
    any of them
}