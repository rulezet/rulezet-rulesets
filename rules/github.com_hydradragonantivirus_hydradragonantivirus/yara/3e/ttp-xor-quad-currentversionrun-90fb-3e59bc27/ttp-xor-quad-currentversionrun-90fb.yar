rule TTP_XOR_QUAD_CurrentVersionRun_90fb {
  strings:
    $key_90fb = { c3 94 [2] e7 9a [2] cc b6 [2] e2 94 [2] f6 8f [2] f9 95 [2] e7 88 [2] e5 89 [2] fe 8f [2] e2 88 [2] fe a7 }

  condition:
    any of them
}