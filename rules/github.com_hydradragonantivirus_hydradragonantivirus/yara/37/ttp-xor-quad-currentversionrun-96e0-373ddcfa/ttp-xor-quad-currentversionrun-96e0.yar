rule TTP_XOR_QUAD_CurrentVersionRun_96e0 {
  strings:
    $key_96e0 = { c5 8f [2] e1 81 [2] ca ad [2] e4 8f [2] f0 94 [2] ff 8e [2] e1 93 [2] e3 92 [2] f8 94 [2] e4 93 [2] f8 bc }

  condition:
    any of them
}