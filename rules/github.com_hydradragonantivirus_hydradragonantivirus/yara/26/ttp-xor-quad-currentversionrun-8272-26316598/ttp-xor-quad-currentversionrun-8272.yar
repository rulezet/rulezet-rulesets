rule TTP_XOR_QUAD_CurrentVersionRun_8272 {
  strings:
    $key_8272 = { d1 1d [2] f5 13 [2] de 3f [2] f0 1d [2] e4 06 [2] eb 1c [2] f5 01 [2] f7 00 [2] ec 06 [2] f0 01 [2] ec 2e }

  condition:
    any of them
}