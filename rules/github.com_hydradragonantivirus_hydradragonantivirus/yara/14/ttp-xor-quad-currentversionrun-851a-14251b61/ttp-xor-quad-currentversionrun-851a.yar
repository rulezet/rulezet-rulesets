rule TTP_XOR_QUAD_CurrentVersionRun_851a {
  strings:
    $key_851a = { d6 75 [2] f2 7b [2] d9 57 [2] f7 75 [2] e3 6e [2] ec 74 [2] f2 69 [2] f0 68 [2] eb 6e [2] f7 69 [2] eb 46 }

  condition:
    any of them
}