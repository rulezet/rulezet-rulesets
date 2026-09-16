rule TTP_XOR_QUAD_CurrentVersionRun_96c8 {
  strings:
    $key_96c8 = { c5 a7 [2] e1 a9 [2] ca 85 [2] e4 a7 [2] f0 bc [2] ff a6 [2] e1 bb [2] e3 ba [2] f8 bc [2] e4 bb [2] f8 94 }

  condition:
    any of them
}