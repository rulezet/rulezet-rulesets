rule TTP_XOR_QUAD_CurrentVersionRun_84c8 {
  strings:
    $key_84c8 = { d7 a7 [2] f3 a9 [2] d8 85 [2] f6 a7 [2] e2 bc [2] ed a6 [2] f3 bb [2] f1 ba [2] ea bc [2] f6 bb [2] ea 94 }

  condition:
    any of them
}