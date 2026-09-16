rule TTP_XOR_QUAD_CurrentVersionRun_e5a5 {
  strings:
    $key_e5a5 = { b6 ca [2] 92 c4 [2] b9 e8 [2] 97 ca [2] 83 d1 [2] 8c cb [2] 92 d6 [2] 90 d7 [2] 8b d1 [2] 97 d6 [2] 8b f9 }

  condition:
    any of them
}