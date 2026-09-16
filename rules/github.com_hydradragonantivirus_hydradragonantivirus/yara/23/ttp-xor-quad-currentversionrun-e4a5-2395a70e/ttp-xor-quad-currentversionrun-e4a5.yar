rule TTP_XOR_QUAD_CurrentVersionRun_e4a5 {
  strings:
    $key_e4a5 = { b7 ca [2] 93 c4 [2] b8 e8 [2] 96 ca [2] 82 d1 [2] 8d cb [2] 93 d6 [2] 91 d7 [2] 8a d1 [2] 96 d6 [2] 8a f9 }

  condition:
    any of them
}