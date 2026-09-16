rule TTP_XOR_QUAD_CurrentVersionRun_96f3 {
  strings:
    $key_96f3 = { c5 9c [2] e1 92 [2] ca be [2] e4 9c [2] f0 87 [2] ff 9d [2] e1 80 [2] e3 81 [2] f8 87 [2] e4 80 [2] f8 af }

  condition:
    any of them
}