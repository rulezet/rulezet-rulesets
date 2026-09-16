rule TTP_XOR_QUAD_CurrentVersionRun_8252 {
  strings:
    $key_8252 = { d1 3d [2] f5 33 [2] de 1f [2] f0 3d [2] e4 26 [2] eb 3c [2] f5 21 [2] f7 20 [2] ec 26 [2] f0 21 [2] ec 0e }

  condition:
    any of them
}