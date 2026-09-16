rule TTP_XOR_QUAD_CurrentVersionRun_958b {
  strings:
    $key_958b = { c6 e4 [2] e2 ea [2] c9 c6 [2] e7 e4 [2] f3 ff [2] fc e5 [2] e2 f8 [2] e0 f9 [2] fb ff [2] e7 f8 [2] fb d7 }

  condition:
    any of them
}