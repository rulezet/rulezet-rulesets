rule TTP_XOR_QUAD_CurrentVersionRun_8413 {
  strings:
    $key_8413 = { d7 7c [2] f3 72 [2] d8 5e [2] f6 7c [2] e2 67 [2] ed 7d [2] f3 60 [2] f1 61 [2] ea 67 [2] f6 60 [2] ea 4f }

  condition:
    any of them
}