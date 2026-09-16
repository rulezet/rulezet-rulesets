rule TTP_XOR_QUAD_CurrentVersionRun_905b {
  strings:
    $key_905b = { c3 34 [2] e7 3a [2] cc 16 [2] e2 34 [2] f6 2f [2] f9 35 [2] e7 28 [2] e5 29 [2] fe 2f [2] e2 28 [2] fe 07 }

  condition:
    any of them
}