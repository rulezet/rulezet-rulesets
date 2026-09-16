rule TTP_XOR_QUAD_CurrentVersionRun_9b61 {
  strings:
    $key_9b61 = { c8 0e [2] ec 00 [2] c7 2c [2] e9 0e [2] fd 15 [2] f2 0f [2] ec 12 [2] ee 13 [2] f5 15 [2] e9 12 [2] f5 3d }

  condition:
    any of them
}