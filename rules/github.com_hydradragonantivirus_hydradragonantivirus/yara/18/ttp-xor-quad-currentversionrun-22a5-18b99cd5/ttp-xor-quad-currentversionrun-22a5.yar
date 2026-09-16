rule TTP_XOR_QUAD_CurrentVersionRun_22a5 {
  strings:
    $key_22a5 = { 71 ca [2] 55 c4 [2] 7e e8 [2] 50 ca [2] 44 d1 [2] 4b cb [2] 55 d6 [2] 57 d7 [2] 4c d1 [2] 50 d6 [2] 4c f9 }

  condition:
    any of them
}