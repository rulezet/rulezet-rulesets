rule TTP_XOR_QUAD_CurrentVersionRun_90d2 {
  strings:
    $key_90d2 = { c3 bd [2] e7 b3 [2] cc 9f [2] e2 bd [2] f6 a6 [2] f9 bc [2] e7 a1 [2] e5 a0 [2] fe a6 [2] e2 a1 [2] fe 8e }

  condition:
    any of them
}