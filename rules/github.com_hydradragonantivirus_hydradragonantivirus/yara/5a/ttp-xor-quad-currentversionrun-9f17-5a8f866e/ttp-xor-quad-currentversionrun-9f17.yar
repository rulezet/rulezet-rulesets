rule TTP_XOR_QUAD_CurrentVersionRun_9f17 {
  strings:
    $key_9f17 = { cc 78 [2] e8 76 [2] c3 5a [2] ed 78 [2] f9 63 [2] f6 79 [2] e8 64 [2] ea 65 [2] f1 63 [2] ed 64 [2] f1 4b }

  condition:
    any of them
}