rule TTP_XOR_QUAD_CurrentVersionRun_9f55 {
  strings:
    $key_9f55 = { cc 3a [2] e8 34 [2] c3 18 [2] ed 3a [2] f9 21 [2] f6 3b [2] e8 26 [2] ea 27 [2] f1 21 [2] ed 26 [2] f1 09 }

  condition:
    any of them
}