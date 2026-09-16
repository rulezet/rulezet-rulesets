rule TTP_XOR_QUAD_CurrentVersionRun_90d5 {
  strings:
    $key_90d5 = { c3 ba [2] e7 b4 [2] cc 98 [2] e2 ba [2] f6 a1 [2] f9 bb [2] e7 a6 [2] e5 a7 [2] fe a1 [2] e2 a6 [2] fe 89 }

  condition:
    any of them
}