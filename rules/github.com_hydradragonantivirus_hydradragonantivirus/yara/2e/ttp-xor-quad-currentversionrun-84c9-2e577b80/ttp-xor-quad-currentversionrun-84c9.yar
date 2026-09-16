rule TTP_XOR_QUAD_CurrentVersionRun_84c9 {
  strings:
    $key_84c9 = { d7 a6 [2] f3 a8 [2] d8 84 [2] f6 a6 [2] e2 bd [2] ed a7 [2] f3 ba [2] f1 bb [2] ea bd [2] f6 ba [2] ea 95 }

  condition:
    any of them
}