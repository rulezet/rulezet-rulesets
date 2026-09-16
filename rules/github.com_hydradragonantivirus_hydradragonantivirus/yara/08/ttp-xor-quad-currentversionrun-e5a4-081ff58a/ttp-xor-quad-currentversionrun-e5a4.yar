rule TTP_XOR_QUAD_CurrentVersionRun_e5a4 {
  strings:
    $key_e5a4 = { b6 cb [2] 92 c5 [2] b9 e9 [2] 97 cb [2] 83 d0 [2] 8c ca [2] 92 d7 [2] 90 d6 [2] 8b d0 [2] 97 d7 [2] 8b f8 }

  condition:
    any of them
}