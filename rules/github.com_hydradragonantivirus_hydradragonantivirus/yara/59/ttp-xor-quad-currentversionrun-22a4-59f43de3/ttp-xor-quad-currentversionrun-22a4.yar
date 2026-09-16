rule TTP_XOR_QUAD_CurrentVersionRun_22a4 {
  strings:
    $key_22a4 = { 71 cb [2] 55 c5 [2] 7e e9 [2] 50 cb [2] 44 d0 [2] 4b ca [2] 55 d7 [2] 57 d6 [2] 4c d0 [2] 50 d7 [2] 4c f8 }

  condition:
    any of them
}