rule TTP_XOR_QUAD_CurrentVersionRun_12a4 {
  strings:
    $key_12a4 = { 41 cb [2] 65 c5 [2] 4e e9 [2] 60 cb [2] 74 d0 [2] 7b ca [2] 65 d7 [2] 67 d6 [2] 7c d0 [2] 60 d7 [2] 7c f8 }

  condition:
    any of them
}