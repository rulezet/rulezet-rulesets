rule TTP_XOR_QUAD_CurrentVersionRun_8250 {
  strings:
    $key_8250 = { d1 3f [2] f5 31 [2] de 1d [2] f0 3f [2] e4 24 [2] eb 3e [2] f5 23 [2] f7 22 [2] ec 24 [2] f0 23 [2] ec 0c }

  condition:
    any of them
}