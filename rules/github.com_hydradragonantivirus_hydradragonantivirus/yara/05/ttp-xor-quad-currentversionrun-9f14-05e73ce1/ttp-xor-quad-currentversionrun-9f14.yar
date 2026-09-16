rule TTP_XOR_QUAD_CurrentVersionRun_9f14 {
  strings:
    $key_9f14 = { cc 7b [2] e8 75 [2] c3 59 [2] ed 7b [2] f9 60 [2] f6 7a [2] e8 67 [2] ea 66 [2] f1 60 [2] ed 67 [2] f1 48 }

  condition:
    any of them
}