rule TTP_XOR_QUAD_CurrentVersionRun_90a4 {
  strings:
    $key_90a4 = { c3 cb [2] e7 c5 [2] cc e9 [2] e2 cb [2] f6 d0 [2] f9 ca [2] e7 d7 [2] e5 d6 [2] fe d0 [2] e2 d7 [2] fe f8 }

  condition:
    any of them
}