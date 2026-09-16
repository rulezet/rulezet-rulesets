rule TTP_XOR_QUAD_CurrentVersionRun_81ad {
  strings:
    $key_81ad = { d2 c2 [2] f6 cc [2] dd e0 [2] f3 c2 [2] e7 d9 [2] e8 c3 [2] f6 de [2] f4 df [2] ef d9 [2] f3 de [2] ef f1 }

  condition:
    any of them
}