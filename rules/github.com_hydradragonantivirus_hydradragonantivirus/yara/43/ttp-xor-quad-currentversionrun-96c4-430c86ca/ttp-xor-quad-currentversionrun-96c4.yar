rule TTP_XOR_QUAD_CurrentVersionRun_96c4 {
  strings:
    $key_96c4 = { c5 ab [2] e1 a5 [2] ca 89 [2] e4 ab [2] f0 b0 [2] ff aa [2] e1 b7 [2] e3 b6 [2] f8 b0 [2] e4 b7 [2] f8 98 }

  condition:
    any of them
}