rule TTP_XOR_QUAD_CurrentVersionRun_827a {
  strings:
    $key_827a = { d1 15 [2] f5 1b [2] de 37 [2] f0 15 [2] e4 0e [2] eb 14 [2] f5 09 [2] f7 08 [2] ec 0e [2] f0 09 [2] ec 26 }

  condition:
    any of them
}