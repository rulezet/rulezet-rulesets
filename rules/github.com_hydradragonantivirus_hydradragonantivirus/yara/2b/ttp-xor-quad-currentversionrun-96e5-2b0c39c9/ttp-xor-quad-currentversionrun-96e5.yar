rule TTP_XOR_QUAD_CurrentVersionRun_96e5 {
  strings:
    $key_96e5 = { c5 8a [2] e1 84 [2] ca a8 [2] e4 8a [2] f0 91 [2] ff 8b [2] e1 96 [2] e3 97 [2] f8 91 [2] e4 96 [2] f8 b9 }

  condition:
    any of them
}