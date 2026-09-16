rule TTP_XOR_QUAD_CurrentVersionRun_50b9 {
  strings:
    $key_50b9 = { 03 d6 [2] 27 d8 [2] 0c f4 [2] 22 d6 [2] 36 cd [2] 39 d7 [2] 27 ca [2] 25 cb [2] 3e cd [2] 22 ca [2] 3e e5 }

  condition:
    any of them
}