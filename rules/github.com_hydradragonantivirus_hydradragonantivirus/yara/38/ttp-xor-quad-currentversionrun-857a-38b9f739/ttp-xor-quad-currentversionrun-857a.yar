rule TTP_XOR_QUAD_CurrentVersionRun_857a {
  strings:
    $key_857a = { d6 15 [2] f2 1b [2] d9 37 [2] f7 15 [2] e3 0e [2] ec 14 [2] f2 09 [2] f0 08 [2] eb 0e [2] f7 09 [2] eb 26 }

  condition:
    any of them
}