rule TTP_XOR_QUAD_CurrentVersionRun_90a5 {
  strings:
    $key_90a5 = { c3 ca [2] e7 c4 [2] cc e8 [2] e2 ca [2] f6 d1 [2] f9 cb [2] e7 d6 [2] e5 d7 [2] fe d1 [2] e2 d6 [2] fe f9 }

  condition:
    any of them
}