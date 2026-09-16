rule TTP_XOR_QUAD_CurrentVersionRun_9f39 {
  strings:
    $key_9f39 = { cc 56 [2] e8 58 [2] c3 74 [2] ed 56 [2] f9 4d [2] f6 57 [2] e8 4a [2] ea 4b [2] f1 4d [2] ed 4a [2] f1 65 }

  condition:
    any of them
}