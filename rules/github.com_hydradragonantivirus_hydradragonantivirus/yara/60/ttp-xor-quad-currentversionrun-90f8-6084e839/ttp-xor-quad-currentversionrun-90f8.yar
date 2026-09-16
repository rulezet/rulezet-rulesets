rule TTP_XOR_QUAD_CurrentVersionRun_90f8 {
  strings:
    $key_90f8 = { c3 97 [2] e7 99 [2] cc b5 [2] e2 97 [2] f6 8c [2] f9 96 [2] e7 8b [2] e5 8a [2] fe 8c [2] e2 8b [2] fe a4 }

  condition:
    any of them
}