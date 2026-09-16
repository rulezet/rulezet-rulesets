rule TTP_XOR_QUAD_CurrentVersionRun_55a4 {
  strings:
    $key_55a4 = { 06 cb [2] 22 c5 [2] 09 e9 [2] 27 cb [2] 33 d0 [2] 3c ca [2] 22 d7 [2] 20 d6 [2] 3b d0 [2] 27 d7 [2] 3b f8 }

  condition:
    any of them
}