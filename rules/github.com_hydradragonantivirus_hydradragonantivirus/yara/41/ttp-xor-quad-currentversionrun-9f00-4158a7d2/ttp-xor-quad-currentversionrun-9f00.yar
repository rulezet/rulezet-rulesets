rule TTP_XOR_QUAD_CurrentVersionRun_9f00 {
  strings:
    $key_9f00 = { cc 6f [2] e8 61 [2] c3 4d [2] ed 6f [2] f9 74 [2] f6 6e [2] e8 73 [2] ea 72 [2] f1 74 [2] ed 73 [2] f1 5c }

  condition:
    any of them
}