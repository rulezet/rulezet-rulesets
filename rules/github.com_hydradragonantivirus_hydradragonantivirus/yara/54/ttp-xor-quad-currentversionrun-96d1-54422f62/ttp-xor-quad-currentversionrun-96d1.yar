rule TTP_XOR_QUAD_CurrentVersionRun_96d1 {
  strings:
    $key_96d1 = { c5 be [2] e1 b0 [2] ca 9c [2] e4 be [2] f0 a5 [2] ff bf [2] e1 a2 [2] e3 a3 [2] f8 a5 [2] e4 a2 [2] f8 8d }

  condition:
    any of them
}