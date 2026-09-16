rule TTP_XOR_QUAD_CurrentVersionRun_81b8 {
  strings:
    $key_81b8 = { d2 d7 [2] f6 d9 [2] dd f5 [2] f3 d7 [2] e7 cc [2] e8 d6 [2] f6 cb [2] f4 ca [2] ef cc [2] f3 cb [2] ef e4 }

  condition:
    any of them
}