rule TTP_XOR_QUAD_CurrentVersionRun_9f20 {
  strings:
    $key_9f20 = { cc 4f [2] e8 41 [2] c3 6d [2] ed 4f [2] f9 54 [2] f6 4e [2] e8 53 [2] ea 52 [2] f1 54 [2] ed 53 [2] f1 7c }

  condition:
    any of them
}