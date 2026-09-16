rule TTP_XOR_QUAD_CurrentVersionRun_97a4 {
  strings:
    $key_97a4 = { c4 cb [2] e0 c5 [2] cb e9 [2] e5 cb [2] f1 d0 [2] fe ca [2] e0 d7 [2] e2 d6 [2] f9 d0 [2] e5 d7 [2] f9 f8 }

  condition:
    any of them
}