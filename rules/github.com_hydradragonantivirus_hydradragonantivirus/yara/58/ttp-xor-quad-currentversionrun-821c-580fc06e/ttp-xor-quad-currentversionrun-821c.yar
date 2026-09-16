rule TTP_XOR_QUAD_CurrentVersionRun_821c {
  strings:
    $key_821c = { d1 73 [2] f5 7d [2] de 51 [2] f0 73 [2] e4 68 [2] eb 72 [2] f5 6f [2] f7 6e [2] ec 68 [2] f0 6f [2] ec 40 }

  condition:
    any of them
}