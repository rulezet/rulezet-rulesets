rule TTP_XOR_QUAD_CurrentVersionRun_9f18 {
  strings:
    $key_9f18 = { cc 77 [2] e8 79 [2] c3 55 [2] ed 77 [2] f9 6c [2] f6 76 [2] e8 6b [2] ea 6a [2] f1 6c [2] ed 6b [2] f1 44 }

  condition:
    any of them
}