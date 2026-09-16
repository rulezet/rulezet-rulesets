rule TTP_XOR_QUAD_CurrentVersionRun_90b6 {
  strings:
    $key_90b6 = { c3 d9 [2] e7 d7 [2] cc fb [2] e2 d9 [2] f6 c2 [2] f9 d8 [2] e7 c5 [2] e5 c4 [2] fe c2 [2] e2 c5 [2] fe ea }

  condition:
    any of them
}