rule TTP_XOR_QUAD_CurrentVersionRun_8200 {
  strings:
    $key_8200 = { d1 6f [2] f5 61 [2] de 4d [2] f0 6f [2] e4 74 [2] eb 6e [2] f5 73 [2] f7 72 [2] ec 74 [2] f0 73 [2] ec 5c }

  condition:
    any of them
}