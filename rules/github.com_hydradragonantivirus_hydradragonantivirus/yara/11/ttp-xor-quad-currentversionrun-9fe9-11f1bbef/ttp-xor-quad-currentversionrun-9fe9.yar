rule TTP_XOR_QUAD_CurrentVersionRun_9fe9 {
  strings:
    $key_9fe9 = { cc 86 [2] e8 88 [2] c3 a4 [2] ed 86 [2] f9 9d [2] f6 87 [2] e8 9a [2] ea 9b [2] f1 9d [2] ed 9a [2] f1 b5 }

  condition:
    any of them
}