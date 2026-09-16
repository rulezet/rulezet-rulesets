rule TTP_XOR_QUAD_CurrentVersionRun_96a4 {
  strings:
    $key_96a4 = { c5 cb [2] e1 c5 [2] ca e9 [2] e4 cb [2] f0 d0 [2] ff ca [2] e1 d7 [2] e3 d6 [2] f8 d0 [2] e4 d7 [2] f8 f8 }

  condition:
    any of them
}