rule TTP_XOR_QUAD_CurrentVersionRun_9f2b {
  strings:
    $key_9f2b = { cc 44 [2] e8 4a [2] c3 66 [2] ed 44 [2] f9 5f [2] f6 45 [2] e8 58 [2] ea 59 [2] f1 5f [2] ed 58 [2] f1 77 }

  condition:
    any of them
}