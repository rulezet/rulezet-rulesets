rule TTP_XOR_QUAD_CurrentVersionRun_94b6 {
  strings:
    $key_94b6 = { c7 d9 [2] e3 d7 [2] c8 fb [2] e6 d9 [2] f2 c2 [2] fd d8 [2] e3 c5 [2] e1 c4 [2] fa c2 [2] e6 c5 [2] fa ea }

  condition:
    any of them
}