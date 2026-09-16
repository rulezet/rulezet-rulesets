rule TTP_XOR_QUAD_CurrentVersionRun_93c9 {
  strings:
    $key_93c9 = { c0 a6 [2] e4 a8 [2] cf 84 [2] e1 a6 [2] f5 bd [2] fa a7 [2] e4 ba [2] e6 bb [2] fd bd [2] e1 ba [2] fd 95 }

  condition:
    any of them
}