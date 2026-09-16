rule TTP_XOR_QUAD_CurrentVersionRun_8233 {
  strings:
    $key_8233 = { d1 5c [2] f5 52 [2] de 7e [2] f0 5c [2] e4 47 [2] eb 5d [2] f5 40 [2] f7 41 [2] ec 47 [2] f0 40 [2] ec 6f }

  condition:
    any of them
}