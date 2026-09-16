rule TTP_XOR_QUAD_CurrentVersionRun_901b {
  strings:
    $key_901b = { c3 74 [2] e7 7a [2] cc 56 [2] e2 74 [2] f6 6f [2] f9 75 [2] e7 68 [2] e5 69 [2] fe 6f [2] e2 68 [2] fe 47 }

  condition:
    any of them
}