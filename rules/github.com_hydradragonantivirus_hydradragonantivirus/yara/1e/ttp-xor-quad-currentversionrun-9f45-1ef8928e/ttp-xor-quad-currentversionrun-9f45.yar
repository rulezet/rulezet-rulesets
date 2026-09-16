rule TTP_XOR_QUAD_CurrentVersionRun_9f45 {
  strings:
    $key_9f45 = { cc 2a [2] e8 24 [2] c3 08 [2] ed 2a [2] f9 31 [2] f6 2b [2] e8 36 [2] ea 37 [2] f1 31 [2] ed 36 [2] f1 19 }

  condition:
    any of them
}