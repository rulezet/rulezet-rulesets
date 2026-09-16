rule TTP_XOR_QUAD_CurrentVersionRun_d0a4 {
  strings:
    $key_d0a4 = { 83 cb [2] a7 c5 [2] 8c e9 [2] a2 cb [2] b6 d0 [2] b9 ca [2] a7 d7 [2] a5 d6 [2] be d0 [2] a2 d7 [2] be f8 }

  condition:
    any of them
}