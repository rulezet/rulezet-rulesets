rule TTP_XOR_QUAD_CurrentVersionRun_8563 {
  strings:
    $key_8563 = { d6 0c [2] f2 02 [2] d9 2e [2] f7 0c [2] e3 17 [2] ec 0d [2] f2 10 [2] f0 11 [2] eb 17 [2] f7 10 [2] eb 3f }

  condition:
    any of them
}