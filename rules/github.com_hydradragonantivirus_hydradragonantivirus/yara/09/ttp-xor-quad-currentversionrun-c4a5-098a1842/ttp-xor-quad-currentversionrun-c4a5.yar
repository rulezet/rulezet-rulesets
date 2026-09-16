rule TTP_XOR_QUAD_CurrentVersionRun_c4a5 {
  strings:
    $key_c4a5 = { 97 ca [2] b3 c4 [2] 98 e8 [2] b6 ca [2] a2 d1 [2] ad cb [2] b3 d6 [2] b1 d7 [2] aa d1 [2] b6 d6 [2] aa f9 }

  condition:
    any of them
}