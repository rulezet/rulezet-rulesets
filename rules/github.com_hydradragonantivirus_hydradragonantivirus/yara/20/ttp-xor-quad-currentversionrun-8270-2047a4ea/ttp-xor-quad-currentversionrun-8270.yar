rule TTP_XOR_QUAD_CurrentVersionRun_8270 {
  strings:
    $key_8270 = { d1 1f [2] f5 11 [2] de 3d [2] f0 1f [2] e4 04 [2] eb 1e [2] f5 03 [2] f7 02 [2] ec 04 [2] f0 03 [2] ec 2c }

  condition:
    any of them
}