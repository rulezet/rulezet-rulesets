rule TTP_XOR_QUAD_CurrentVersionRun_9f44 {
  strings:
    $key_9f44 = { cc 2b [2] e8 25 [2] c3 09 [2] ed 2b [2] f9 30 [2] f6 2a [2] e8 37 [2] ea 36 [2] f1 30 [2] ed 37 [2] f1 18 }

  condition:
    any of them
}