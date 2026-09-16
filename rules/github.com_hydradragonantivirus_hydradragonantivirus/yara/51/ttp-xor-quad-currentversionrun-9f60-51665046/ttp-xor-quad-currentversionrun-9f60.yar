rule TTP_XOR_QUAD_CurrentVersionRun_9f60 {
  strings:
    $key_9f60 = { cc 0f [2] e8 01 [2] c3 2d [2] ed 0f [2] f9 14 [2] f6 0e [2] e8 13 [2] ea 12 [2] f1 14 [2] ed 13 [2] f1 3c }

  condition:
    any of them
}