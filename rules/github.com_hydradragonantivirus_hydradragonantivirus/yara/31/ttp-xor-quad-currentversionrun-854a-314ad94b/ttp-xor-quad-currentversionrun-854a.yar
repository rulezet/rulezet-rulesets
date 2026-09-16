rule TTP_XOR_QUAD_CurrentVersionRun_854a {
  strings:
    $key_854a = { d6 25 [2] f2 2b [2] d9 07 [2] f7 25 [2] e3 3e [2] ec 24 [2] f2 39 [2] f0 38 [2] eb 3e [2] f7 39 [2] eb 16 }

  condition:
    any of them
}