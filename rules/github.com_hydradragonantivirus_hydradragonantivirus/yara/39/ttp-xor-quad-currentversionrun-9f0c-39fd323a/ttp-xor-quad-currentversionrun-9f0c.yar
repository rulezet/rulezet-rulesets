rule TTP_XOR_QUAD_CurrentVersionRun_9f0c {
  strings:
    $key_9f0c = { cc 63 [2] e8 6d [2] c3 41 [2] ed 63 [2] f9 78 [2] f6 62 [2] e8 7f [2] ea 7e [2] f1 78 [2] ed 7f [2] f1 50 }

  condition:
    any of them
}