rule TTP_XOR_QUAD_CurrentVersionRun_9f3d {
  strings:
    $key_9f3d = { cc 52 [2] e8 5c [2] c3 70 [2] ed 52 [2] f9 49 [2] f6 53 [2] e8 4e [2] ea 4f [2] f1 49 [2] ed 4e [2] f1 61 }

  condition:
    any of them
}