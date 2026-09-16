rule TTP_XOR_QUAD_CurrentVersionRun_9015 {
  strings:
    $key_9015 = { c3 7a [2] e7 74 [2] cc 58 [2] e2 7a [2] f6 61 [2] f9 7b [2] e7 66 [2] e5 67 [2] fe 61 [2] e2 66 [2] fe 49 }

  condition:
    any of them
}