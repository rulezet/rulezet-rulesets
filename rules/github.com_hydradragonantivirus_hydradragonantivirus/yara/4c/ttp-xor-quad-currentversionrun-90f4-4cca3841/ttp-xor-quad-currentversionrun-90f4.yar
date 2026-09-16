rule TTP_XOR_QUAD_CurrentVersionRun_90f4 {
  strings:
    $key_90f4 = { c3 9b [2] e7 95 [2] cc b9 [2] e2 9b [2] f6 80 [2] f9 9a [2] e7 87 [2] e5 86 [2] fe 80 [2] e2 87 [2] fe a8 }

  condition:
    any of them
}