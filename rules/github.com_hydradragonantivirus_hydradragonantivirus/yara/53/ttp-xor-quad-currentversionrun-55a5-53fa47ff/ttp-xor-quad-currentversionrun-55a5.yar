rule TTP_XOR_QUAD_CurrentVersionRun_55a5 {
  strings:
    $key_55a5 = { 06 ca [2] 22 c4 [2] 09 e8 [2] 27 ca [2] 33 d1 [2] 3c cb [2] 22 d6 [2] 20 d7 [2] 3b d1 [2] 27 d6 [2] 3b f9 }

  condition:
    any of them
}