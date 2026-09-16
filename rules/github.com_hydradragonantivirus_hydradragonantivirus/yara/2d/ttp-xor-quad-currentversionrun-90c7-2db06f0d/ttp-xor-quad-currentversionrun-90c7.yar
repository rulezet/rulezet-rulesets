rule TTP_XOR_QUAD_CurrentVersionRun_90c7 {
  strings:
    $key_90c7 = { c3 a8 [2] e7 a6 [2] cc 8a [2] e2 a8 [2] f6 b3 [2] f9 a9 [2] e7 b4 [2] e5 b5 [2] fe b3 [2] e2 b4 [2] fe 9b }

  condition:
    any of them
}