rule TTP_XOR_QUAD_CurrentVersionRun_9f54 {
  strings:
    $key_9f54 = { cc 3b [2] e8 35 [2] c3 19 [2] ed 3b [2] f9 20 [2] f6 3a [2] e8 27 [2] ea 26 [2] f1 20 [2] ed 27 [2] f1 08 }

  condition:
    any of them
}