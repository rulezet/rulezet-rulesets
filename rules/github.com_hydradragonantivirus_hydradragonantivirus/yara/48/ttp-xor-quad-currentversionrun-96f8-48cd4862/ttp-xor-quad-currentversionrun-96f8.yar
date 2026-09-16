rule TTP_XOR_QUAD_CurrentVersionRun_96f8 {
  strings:
    $key_96f8 = { c5 97 [2] e1 99 [2] ca b5 [2] e4 97 [2] f0 8c [2] ff 96 [2] e1 8b [2] e3 8a [2] f8 8c [2] e4 8b [2] f8 a4 }

  condition:
    any of them
}