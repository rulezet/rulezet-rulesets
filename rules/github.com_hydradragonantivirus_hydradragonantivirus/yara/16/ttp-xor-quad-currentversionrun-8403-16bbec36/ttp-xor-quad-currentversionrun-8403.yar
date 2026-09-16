rule TTP_XOR_QUAD_CurrentVersionRun_8403 {
  strings:
    $key_8403 = { d7 6c [2] f3 62 [2] d8 4e [2] f6 6c [2] e2 77 [2] ed 6d [2] f3 70 [2] f1 71 [2] ea 77 [2] f6 70 [2] ea 5f }

  condition:
    any of them
}