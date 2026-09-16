rule TTP_XOR_QUAD_CurrentVersionRun_92a5 {
  strings:
    $key_92a5 = { c1 ca [2] e5 c4 [2] ce e8 [2] e0 ca [2] f4 d1 [2] fb cb [2] e5 d6 [2] e7 d7 [2] fc d1 [2] e0 d6 [2] fc f9 }

  condition:
    any of them
}