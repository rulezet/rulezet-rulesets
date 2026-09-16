rule TTP_XOR_QUAD_CurrentVersionRun_9026 {
  strings:
    $key_9026 = { c3 49 [2] e7 47 [2] cc 6b [2] e2 49 [2] f6 52 [2] f9 48 [2] e7 55 [2] e5 54 [2] fe 52 [2] e2 55 [2] fe 7a }

  condition:
    any of them
}