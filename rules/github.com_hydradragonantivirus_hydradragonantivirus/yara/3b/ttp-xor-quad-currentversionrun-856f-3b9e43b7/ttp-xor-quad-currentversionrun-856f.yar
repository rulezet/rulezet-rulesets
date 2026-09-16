rule TTP_XOR_QUAD_CurrentVersionRun_856f {
  strings:
    $key_856f = { d6 00 [2] f2 0e [2] d9 22 [2] f7 00 [2] e3 1b [2] ec 01 [2] f2 1c [2] f0 1d [2] eb 1b [2] f7 1c [2] eb 33 }

  condition:
    any of them
}