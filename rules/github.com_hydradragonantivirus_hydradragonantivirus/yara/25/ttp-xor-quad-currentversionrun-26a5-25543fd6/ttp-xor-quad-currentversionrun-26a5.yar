rule TTP_XOR_QUAD_CurrentVersionRun_26a5 {
  strings:
    $key_26a5 = { 75 ca [2] 51 c4 [2] 7a e8 [2] 54 ca [2] 40 d1 [2] 4f cb [2] 51 d6 [2] 53 d7 [2] 48 d1 [2] 54 d6 [2] 48 f9 }

  condition:
    any of them
}