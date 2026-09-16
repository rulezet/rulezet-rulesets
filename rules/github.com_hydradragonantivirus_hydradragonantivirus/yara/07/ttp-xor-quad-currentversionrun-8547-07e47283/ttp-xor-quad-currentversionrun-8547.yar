rule TTP_XOR_QUAD_CurrentVersionRun_8547 {
  strings:
    $key_8547 = { d6 28 [2] f2 26 [2] d9 0a [2] f7 28 [2] e3 33 [2] ec 29 [2] f2 34 [2] f0 35 [2] eb 33 [2] f7 34 [2] eb 1b }

  condition:
    any of them
}