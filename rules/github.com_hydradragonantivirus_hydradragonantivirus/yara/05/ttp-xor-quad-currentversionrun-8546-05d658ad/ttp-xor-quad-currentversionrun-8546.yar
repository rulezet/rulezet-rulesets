rule TTP_XOR_QUAD_CurrentVersionRun_8546 {
  strings:
    $key_8546 = { d6 29 [2] f2 27 [2] d9 0b [2] f7 29 [2] e3 32 [2] ec 28 [2] f2 35 [2] f0 34 [2] eb 32 [2] f7 35 [2] eb 1a }

  condition:
    any of them
}