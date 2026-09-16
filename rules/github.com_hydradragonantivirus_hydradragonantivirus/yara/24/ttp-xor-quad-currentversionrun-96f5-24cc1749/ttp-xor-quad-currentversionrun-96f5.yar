rule TTP_XOR_QUAD_CurrentVersionRun_96f5 {
  strings:
    $key_96f5 = { c5 9a [2] e1 94 [2] ca b8 [2] e4 9a [2] f0 81 [2] ff 9b [2] e1 86 [2] e3 87 [2] f8 81 [2] e4 86 [2] f8 a9 }

  condition:
    any of them
}