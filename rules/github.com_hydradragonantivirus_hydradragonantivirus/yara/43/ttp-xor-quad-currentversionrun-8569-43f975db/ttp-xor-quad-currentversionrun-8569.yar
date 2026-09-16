rule TTP_XOR_QUAD_CurrentVersionRun_8569 {
  strings:
    $key_8569 = { d6 06 [2] f2 08 [2] d9 24 [2] f7 06 [2] e3 1d [2] ec 07 [2] f2 1a [2] f0 1b [2] eb 1d [2] f7 1a [2] eb 35 }

  condition:
    any of them
}