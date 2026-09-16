rule TTP_XOR_QUAD_CurrentVersionRun_daa4 {
  strings:
    $key_daa4 = { 89 cb [2] ad c5 [2] 86 e9 [2] a8 cb [2] bc d0 [2] b3 ca [2] ad d7 [2] af d6 [2] b4 d0 [2] a8 d7 [2] b4 f8 }

  condition:
    any of them
}