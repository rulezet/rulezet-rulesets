rule TTP_XOR_QUAD_CurrentVersionRun_97b6 {
  strings:
    $key_97b6 = { c4 d9 [2] e0 d7 [2] cb fb [2] e5 d9 [2] f1 c2 [2] fe d8 [2] e0 c5 [2] e2 c4 [2] f9 c2 [2] e5 c5 [2] f9 ea }

  condition:
    any of them
}