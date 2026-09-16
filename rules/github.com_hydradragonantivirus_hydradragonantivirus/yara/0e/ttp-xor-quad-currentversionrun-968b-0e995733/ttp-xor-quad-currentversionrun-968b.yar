rule TTP_XOR_QUAD_CurrentVersionRun_968b {
  strings:
    $key_968b = { c5 e4 [2] e1 ea [2] ca c6 [2] e4 e4 [2] f0 ff [2] ff e5 [2] e1 f8 [2] e3 f9 [2] f8 ff [2] e4 f8 [2] f8 d7 }

  condition:
    any of them
}