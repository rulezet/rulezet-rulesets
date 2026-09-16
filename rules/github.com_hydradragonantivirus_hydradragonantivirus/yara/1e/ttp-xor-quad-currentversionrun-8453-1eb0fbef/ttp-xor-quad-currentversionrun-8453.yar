rule TTP_XOR_QUAD_CurrentVersionRun_8453 {
  strings:
    $key_8453 = { d7 3c [2] f3 32 [2] d8 1e [2] f6 3c [2] e2 27 [2] ed 3d [2] f3 20 [2] f1 21 [2] ea 27 [2] f6 20 [2] ea 0f }

  condition:
    any of them
}