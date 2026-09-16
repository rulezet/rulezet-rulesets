rule TTP_XOR_QUAD_CurrentVersionRun_9f29 {
  strings:
    $key_9f29 = { cc 46 [2] e8 48 [2] c3 64 [2] ed 46 [2] f9 5d [2] f6 47 [2] e8 5a [2] ea 5b [2] f1 5d [2] ed 5a [2] f1 75 }

  condition:
    any of them
}