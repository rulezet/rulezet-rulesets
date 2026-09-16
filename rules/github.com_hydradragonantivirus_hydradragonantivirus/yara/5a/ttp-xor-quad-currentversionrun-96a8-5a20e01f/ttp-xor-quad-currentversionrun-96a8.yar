rule TTP_XOR_QUAD_CurrentVersionRun_96a8 {
  strings:
    $key_96a8 = { c5 c7 [2] e1 c9 [2] ca e5 [2] e4 c7 [2] f0 dc [2] ff c6 [2] e1 db [2] e3 da [2] f8 dc [2] e4 db [2] f8 f4 }

  condition:
    any of them
}