rule TTP_XOR_QUAD_CurrentVersionRun_8503 {
  strings:
    $key_8503 = { d6 6c [2] f2 62 [2] d9 4e [2] f7 6c [2] e3 77 [2] ec 6d [2] f2 70 [2] f0 71 [2] eb 77 [2] f7 70 [2] eb 5f }

  condition:
    any of them
}