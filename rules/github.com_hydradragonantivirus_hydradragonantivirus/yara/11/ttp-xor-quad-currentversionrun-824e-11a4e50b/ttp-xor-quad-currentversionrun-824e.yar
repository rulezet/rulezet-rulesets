rule TTP_XOR_QUAD_CurrentVersionRun_824e {
  strings:
    $key_824e = { d1 21 [2] f5 2f [2] de 03 [2] f0 21 [2] e4 3a [2] eb 20 [2] f5 3d [2] f7 3c [2] ec 3a [2] f0 3d [2] ec 12 }

  condition:
    any of them
}