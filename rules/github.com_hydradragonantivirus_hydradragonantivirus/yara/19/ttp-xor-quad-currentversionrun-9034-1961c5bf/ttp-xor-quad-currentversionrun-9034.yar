rule TTP_XOR_QUAD_CurrentVersionRun_9034 {
  strings:
    $key_9034 = { c3 5b [2] e7 55 [2] cc 79 [2] e2 5b [2] f6 40 [2] f9 5a [2] e7 47 [2] e5 46 [2] fe 40 [2] e2 47 [2] fe 68 }

  condition:
    any of them
}