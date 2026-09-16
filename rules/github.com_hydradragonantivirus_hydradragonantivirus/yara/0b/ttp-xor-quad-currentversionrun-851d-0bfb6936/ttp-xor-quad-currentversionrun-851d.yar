rule TTP_XOR_QUAD_CurrentVersionRun_851d {
  strings:
    $key_851d = { d6 72 [2] f2 7c [2] d9 50 [2] f7 72 [2] e3 69 [2] ec 73 [2] f2 6e [2] f0 6f [2] eb 69 [2] f7 6e [2] eb 41 }

  condition:
    any of them
}