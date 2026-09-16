rule TTP_XOR_QUAD_CurrentVersionRun_8353 {
  strings:
    $key_8353 = { d0 3c [2] f4 32 [2] df 1e [2] f1 3c [2] e5 27 [2] ea 3d [2] f4 20 [2] f6 21 [2] ed 27 [2] f1 20 [2] ed 0f }

  condition:
    any of them
}