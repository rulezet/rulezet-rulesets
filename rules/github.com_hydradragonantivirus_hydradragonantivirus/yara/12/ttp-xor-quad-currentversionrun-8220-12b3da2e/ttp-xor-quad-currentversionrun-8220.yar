rule TTP_XOR_QUAD_CurrentVersionRun_8220 {
  strings:
    $key_8220 = { d1 4f [2] f5 41 [2] de 6d [2] f0 4f [2] e4 54 [2] eb 4e [2] f5 53 [2] f7 52 [2] ec 54 [2] f0 53 [2] ec 7c }

  condition:
    any of them
}