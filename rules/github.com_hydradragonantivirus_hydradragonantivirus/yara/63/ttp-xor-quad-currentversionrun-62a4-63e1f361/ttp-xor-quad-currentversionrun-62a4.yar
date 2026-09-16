rule TTP_XOR_QUAD_CurrentVersionRun_62a4 {
  strings:
    $key_62a4 = { 31 cb [2] 15 c5 [2] 3e e9 [2] 10 cb [2] 04 d0 [2] 0b ca [2] 15 d7 [2] 17 d6 [2] 0c d0 [2] 10 d7 [2] 0c f8 }

  condition:
    any of them
}