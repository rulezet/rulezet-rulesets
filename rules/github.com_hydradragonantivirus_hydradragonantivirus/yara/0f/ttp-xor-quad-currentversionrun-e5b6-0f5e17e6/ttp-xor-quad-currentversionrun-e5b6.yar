rule TTP_XOR_QUAD_CurrentVersionRun_e5b6 {
  strings:
    $key_e5b6 = { b6 d9 [2] 92 d7 [2] b9 fb [2] 97 d9 [2] 83 c2 [2] 8c d8 [2] 92 c5 [2] 90 c4 [2] 8b c2 [2] 97 c5 [2] 8b ea }

  condition:
    any of them
}