rule TTP_XOR_QUAD_CurrentVersionRun_9078 {
  strings:
    $key_9078 = { c3 17 [2] e7 19 [2] cc 35 [2] e2 17 [2] f6 0c [2] f9 16 [2] e7 0b [2] e5 0a [2] fe 0c [2] e2 0b [2] fe 24 }

  condition:
    any of them
}