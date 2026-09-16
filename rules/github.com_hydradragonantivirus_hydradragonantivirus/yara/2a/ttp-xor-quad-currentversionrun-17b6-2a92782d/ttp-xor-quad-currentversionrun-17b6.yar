rule TTP_XOR_QUAD_CurrentVersionRun_17b6 {
  strings:
    $key_17b6 = { 44 d9 [2] 60 d7 [2] 4b fb [2] 65 d9 [2] 71 c2 [2] 7e d8 [2] 60 c5 [2] 62 c4 [2] 79 c2 [2] 65 c5 [2] 79 ea }

  condition:
    any of them
}