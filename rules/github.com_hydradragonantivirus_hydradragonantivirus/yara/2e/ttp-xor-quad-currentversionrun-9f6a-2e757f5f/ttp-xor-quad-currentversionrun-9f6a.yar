rule TTP_XOR_QUAD_CurrentVersionRun_9f6a {
  strings:
    $key_9f6a = { cc 05 [2] e8 0b [2] c3 27 [2] ed 05 [2] f9 1e [2] f6 04 [2] e8 19 [2] ea 18 [2] f1 1e [2] ed 19 [2] f1 36 }

  condition:
    any of them
}