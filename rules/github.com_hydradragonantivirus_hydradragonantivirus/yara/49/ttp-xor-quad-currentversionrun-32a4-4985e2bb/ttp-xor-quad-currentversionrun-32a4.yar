rule TTP_XOR_QUAD_CurrentVersionRun_32a4 {
  strings:
    $key_32a4 = { 61 cb [2] 45 c5 [2] 6e e9 [2] 40 cb [2] 54 d0 [2] 5b ca [2] 45 d7 [2] 47 d6 [2] 5c d0 [2] 40 d7 [2] 5c f8 }

  condition:
    any of them
}