rule TTP_XOR_QUAD_CurrentVersionRun_9f6e {
  strings:
    $key_9f6e = { cc 01 [2] e8 0f [2] c3 23 [2] ed 01 [2] f9 1a [2] f6 00 [2] e8 1d [2] ea 1c [2] f1 1a [2] ed 1d [2] f1 32 }

  condition:
    any of them
}