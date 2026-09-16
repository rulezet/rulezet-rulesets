rule TTP_XOR_QUAD_CurrentVersionRun_9f4f {
  strings:
    $key_9f4f = { cc 20 [2] e8 2e [2] c3 02 [2] ed 20 [2] f9 3b [2] f6 21 [2] e8 3c [2] ea 3d [2] f1 3b [2] ed 3c [2] f1 13 }

  condition:
    any of them
}