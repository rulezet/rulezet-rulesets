rule TTP_XOR_QUAD_CurrentVersionRun_9ff8 {
  strings:
    $key_9ff8 = { cc 97 [2] e8 99 [2] c3 b5 [2] ed 97 [2] f9 8c [2] f6 96 [2] e8 8b [2] ea 8a [2] f1 8c [2] ed 8b [2] f1 a4 }

  condition:
    any of them
}