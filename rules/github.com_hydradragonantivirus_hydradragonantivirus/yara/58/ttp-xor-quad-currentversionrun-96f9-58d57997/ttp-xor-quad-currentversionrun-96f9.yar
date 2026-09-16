rule TTP_XOR_QUAD_CurrentVersionRun_96f9 {
  strings:
    $key_96f9 = { c5 96 [2] e1 98 [2] ca b4 [2] e4 96 [2] f0 8d [2] ff 97 [2] e1 8a [2] e3 8b [2] f8 8d [2] e4 8a [2] f8 a5 }

  condition:
    any of them
}