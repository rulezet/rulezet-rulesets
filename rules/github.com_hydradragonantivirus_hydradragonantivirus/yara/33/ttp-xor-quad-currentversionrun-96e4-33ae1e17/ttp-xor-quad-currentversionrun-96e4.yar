rule TTP_XOR_QUAD_CurrentVersionRun_96e4 {
  strings:
    $key_96e4 = { c5 8b [2] e1 85 [2] ca a9 [2] e4 8b [2] f0 90 [2] ff 8a [2] e1 97 [2] e3 96 [2] f8 90 [2] e4 97 [2] f8 b8 }

  condition:
    any of them
}