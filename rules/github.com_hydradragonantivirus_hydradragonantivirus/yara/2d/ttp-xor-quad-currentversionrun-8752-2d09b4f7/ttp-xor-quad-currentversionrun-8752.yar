rule TTP_XOR_QUAD_CurrentVersionRun_8752 {
  strings:
    $key_8752 = { d4 3d [2] f0 33 [2] db 1f [2] f5 3d [2] e1 26 [2] ee 3c [2] f0 21 [2] f2 20 [2] e9 26 [2] f5 21 [2] e9 0e }

  condition:
    any of them
}