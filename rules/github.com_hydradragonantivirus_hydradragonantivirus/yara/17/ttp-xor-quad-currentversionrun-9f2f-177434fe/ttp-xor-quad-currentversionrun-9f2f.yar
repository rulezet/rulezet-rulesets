rule TTP_XOR_QUAD_CurrentVersionRun_9f2f {
  strings:
    $key_9f2f = { cc 40 [2] e8 4e [2] c3 62 [2] ed 40 [2] f9 5b [2] f6 41 [2] e8 5c [2] ea 5d [2] f1 5b [2] ed 5c [2] f1 73 }

  condition:
    any of them
}