rule TTP_XOR_QUAD_CurrentVersionRun_9f7a {
  strings:
    $key_9f7a = { cc 15 [2] e8 1b [2] c3 37 [2] ed 15 [2] f9 0e [2] f6 14 [2] e8 09 [2] ea 08 [2] f1 0e [2] ed 09 [2] f1 26 }

  condition:
    any of them
}