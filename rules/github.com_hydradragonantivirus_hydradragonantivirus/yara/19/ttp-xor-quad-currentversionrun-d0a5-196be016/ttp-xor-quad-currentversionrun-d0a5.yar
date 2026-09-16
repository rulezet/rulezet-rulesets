rule TTP_XOR_QUAD_CurrentVersionRun_d0a5 {
  strings:
    $key_d0a5 = { 83 ca [2] a7 c4 [2] 8c e8 [2] a2 ca [2] b6 d1 [2] b9 cb [2] a7 d6 [2] a5 d7 [2] be d1 [2] a2 d6 [2] be f9 }

  condition:
    any of them
}