rule TTP_XOR_QUAD_CurrentVersionRun_96b4 {
  strings:
    $key_96b4 = { c5 db [2] e1 d5 [2] ca f9 [2] e4 db [2] f0 c0 [2] ff da [2] e1 c7 [2] e3 c6 [2] f8 c0 [2] e4 c7 [2] f8 e8 }

  condition:
    any of them
}