rule TTP_XOR_QUAD_CurrentVersionRun_96a6 {
  strings:
    $key_96a6 = { c5 c9 [2] e1 c7 [2] ca eb [2] e4 c9 [2] f0 d2 [2] ff c8 [2] e1 d5 [2] e3 d4 [2] f8 d2 [2] e4 d5 [2] f8 fa }

  condition:
    any of them
}