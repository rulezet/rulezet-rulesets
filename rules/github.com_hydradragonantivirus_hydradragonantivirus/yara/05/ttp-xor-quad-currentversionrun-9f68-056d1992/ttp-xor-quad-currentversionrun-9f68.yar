rule TTP_XOR_QUAD_CurrentVersionRun_9f68 {
  strings:
    $key_9f68 = { cc 07 [2] e8 09 [2] c3 25 [2] ed 07 [2] f9 1c [2] f6 06 [2] e8 1b [2] ea 1a [2] f1 1c [2] ed 1b [2] f1 34 }

  condition:
    any of them
}