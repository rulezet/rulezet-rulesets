rule TTP_XOR_QUAD_CurrentVersionRun_94b4 {
  strings:
    $key_94b4 = { c7 db [2] e3 d5 [2] c8 f9 [2] e6 db [2] f2 c0 [2] fd da [2] e3 c7 [2] e1 c6 [2] fa c0 [2] e6 c7 [2] fa e8 }

  condition:
    any of them
}