rule TTP_XOR_QUAD_CurrentVersionRun_94b7 {
  strings:
    $key_94b7 = { c7 d8 [2] e3 d6 [2] c8 fa [2] e6 d8 [2] f2 c3 [2] fd d9 [2] e3 c4 [2] e1 c5 [2] fa c3 [2] e6 c4 [2] fa eb }

  condition:
    any of them
}