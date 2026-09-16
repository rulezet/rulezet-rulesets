rule TTP_XOR_QUAD_CurrentVersionRun_9f1c {
  strings:
    $key_9f1c = { cc 73 [2] e8 7d [2] c3 51 [2] ed 73 [2] f9 68 [2] f6 72 [2] e8 6f [2] ea 6e [2] f1 68 [2] ed 6f [2] f1 40 }

  condition:
    any of them
}