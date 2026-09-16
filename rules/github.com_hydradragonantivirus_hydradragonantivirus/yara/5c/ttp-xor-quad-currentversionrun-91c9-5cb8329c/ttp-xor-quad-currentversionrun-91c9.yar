rule TTP_XOR_QUAD_CurrentVersionRun_91c9 {
  strings:
    $key_91c9 = { c2 a6 [2] e6 a8 [2] cd 84 [2] e3 a6 [2] f7 bd [2] f8 a7 [2] e6 ba [2] e4 bb [2] ff bd [2] e3 ba [2] ff 95 }

  condition:
    any of them
}