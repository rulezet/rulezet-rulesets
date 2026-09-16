rule TTP_XOR_QUAD_CurrentVersionRun_90ca {
  strings:
    $key_90ca = { c3 a5 [2] e7 ab [2] cc 87 [2] e2 a5 [2] f6 be [2] f9 a4 [2] e7 b9 [2] e5 b8 [2] fe be [2] e2 b9 [2] fe 96 }

  condition:
    any of them
}