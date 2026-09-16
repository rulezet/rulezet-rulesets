rule TTP_XOR_QUAD_CurrentVersionRun_86ad {
  strings:
    $key_86ad = { d5 c2 [2] f1 cc [2] da e0 [2] f4 c2 [2] e0 d9 [2] ef c3 [2] f1 de [2] f3 df [2] e8 d9 [2] f4 de [2] e8 f1 }

  condition:
    any of them
}