rule TTP_XOR_QUAD_CurrentVersionRun_86b9 {
  strings:
    $key_86b9 = { d5 d6 [2] f1 d8 [2] da f4 [2] f4 d6 [2] e0 cd [2] ef d7 [2] f1 ca [2] f3 cb [2] e8 cd [2] f4 ca [2] e8 e5 }

  condition:
    any of them
}