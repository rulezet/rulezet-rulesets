rule TTP_XOR_QUAD_CurrentVersionRun_855a {
  strings:
    $key_855a = { d6 35 [2] f2 3b [2] d9 17 [2] f7 35 [2] e3 2e [2] ec 34 [2] f2 29 [2] f0 28 [2] eb 2e [2] f7 29 [2] eb 06 }

  condition:
    any of them
}