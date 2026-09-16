rule TTP_XOR_QUAD_CurrentVersionRun_86c9 {
  strings:
    $key_86c9 = { d5 a6 [2] f1 a8 [2] da 84 [2] f4 a6 [2] e0 bd [2] ef a7 [2] f1 ba [2] f3 bb [2] e8 bd [2] f4 ba [2] e8 95 }

  condition:
    any of them
}