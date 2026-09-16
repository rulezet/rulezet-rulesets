rule TTP_XOR_QUAD_CurrentVersionRun_90c6 {
  strings:
    $key_90c6 = { c3 a9 [2] e7 a7 [2] cc 8b [2] e2 a9 [2] f6 b2 [2] f9 a8 [2] e7 b5 [2] e5 b4 [2] fe b2 [2] e2 b5 [2] fe 9a }

  condition:
    any of them
}