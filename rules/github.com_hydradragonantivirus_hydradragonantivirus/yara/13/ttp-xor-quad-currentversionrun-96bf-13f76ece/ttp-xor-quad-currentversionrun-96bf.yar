rule TTP_XOR_QUAD_CurrentVersionRun_96bf {
  strings:
    $key_96bf = { c5 d0 [2] e1 de [2] ca f2 [2] e4 d0 [2] f0 cb [2] ff d1 [2] e1 cc [2] e3 cd [2] f8 cb [2] e4 cc [2] f8 e3 }

  condition:
    any of them
}