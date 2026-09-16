rule TTP_XOR_QUAD_CurrentVersionRun_96eb {
  strings:
    $key_96eb = { c5 84 [2] e1 8a [2] ca a6 [2] e4 84 [2] f0 9f [2] ff 85 [2] e1 98 [2] e3 99 [2] f8 9f [2] e4 98 [2] f8 b7 }

  condition:
    any of them
}