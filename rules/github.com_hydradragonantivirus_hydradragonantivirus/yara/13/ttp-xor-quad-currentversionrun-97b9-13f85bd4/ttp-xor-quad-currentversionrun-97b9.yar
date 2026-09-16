rule TTP_XOR_QUAD_CurrentVersionRun_97b9 {
  strings:
    $key_97b9 = { c4 d6 [2] e0 d8 [2] cb f4 [2] e5 d6 [2] f1 cd [2] fe d7 [2] e0 ca [2] e2 cb [2] f9 cd [2] e5 ca [2] f9 e5 }

  condition:
    any of them
}