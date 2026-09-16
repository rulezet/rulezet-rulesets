rule TTP_XOR_QUAD_CurrentVersionRun_8fa4 {
  strings:
    $key_8fa4 = { dc cb [2] f8 c5 [2] d3 e9 [2] fd cb [2] e9 d0 [2] e6 ca [2] f8 d7 [2] fa d6 [2] e1 d0 [2] fd d7 [2] e1 f8 }

  condition:
    any of them
}