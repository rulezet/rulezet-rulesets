rule TTP_XOR_QUAD_CurrentVersionRun_90f3 {
  strings:
    $key_90f3 = { c3 9c [2] e7 92 [2] cc be [2] e2 9c [2] f6 87 [2] f9 9d [2] e7 80 [2] e5 81 [2] fe 87 [2] e2 80 [2] fe af }

  condition:
    any of them
}