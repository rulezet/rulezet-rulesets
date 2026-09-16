rule TTP_XOR_QUAD_CurrentVersionRun_25b6 {
  strings:
    $key_25b6 = { 76 d9 [2] 52 d7 [2] 79 fb [2] 57 d9 [2] 43 c2 [2] 4c d8 [2] 52 c5 [2] 50 c4 [2] 4b c2 [2] 57 c5 [2] 4b ea }

  condition:
    any of them
}