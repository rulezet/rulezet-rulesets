rule TTP_XOR_QUAD_CurrentVersionRun_8203 {
  strings:
    $key_8203 = { d1 6c [2] f5 62 [2] de 4e [2] f0 6c [2] e4 77 [2] eb 6d [2] f5 70 [2] f7 71 [2] ec 77 [2] f0 70 [2] ec 5f }

  condition:
    any of them
}