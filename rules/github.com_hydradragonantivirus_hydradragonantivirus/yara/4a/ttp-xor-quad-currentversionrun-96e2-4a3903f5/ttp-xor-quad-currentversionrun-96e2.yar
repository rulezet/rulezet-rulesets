rule TTP_XOR_QUAD_CurrentVersionRun_96e2 {
  strings:
    $key_96e2 = { c5 8d [2] e1 83 [2] ca af [2] e4 8d [2] f0 96 [2] ff 8c [2] e1 91 [2] e3 90 [2] f8 96 [2] e4 91 [2] f8 be }

  condition:
    any of them
}