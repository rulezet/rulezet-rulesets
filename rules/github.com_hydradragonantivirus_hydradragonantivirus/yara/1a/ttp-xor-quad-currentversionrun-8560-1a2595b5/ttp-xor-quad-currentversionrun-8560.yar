rule TTP_XOR_QUAD_CurrentVersionRun_8560 {
  strings:
    $key_8560 = { d6 0f [2] f2 01 [2] d9 2d [2] f7 0f [2] e3 14 [2] ec 0e [2] f2 13 [2] f0 12 [2] eb 14 [2] f7 13 [2] eb 3c }

  condition:
    any of them
}