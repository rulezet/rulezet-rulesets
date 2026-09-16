rule TTP_XOR_QUAD_CurrentVersionRun_72a5 {
  strings:
    $key_72a5 = { 21 ca [2] 05 c4 [2] 2e e8 [2] 00 ca [2] 14 d1 [2] 1b cb [2] 05 d6 [2] 07 d7 [2] 1c d1 [2] 00 d6 [2] 1c f9 }

  condition:
    any of them
}