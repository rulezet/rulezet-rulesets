rule TTP_XOR_QUAD_CurrentVersionRun_9f4b {
  strings:
    $key_9f4b = { cc 24 [2] e8 2a [2] c3 06 [2] ed 24 [2] f9 3f [2] f6 25 [2] e8 38 [2] ea 39 [2] f1 3f [2] ed 38 [2] f1 17 }

  condition:
    any of them
}