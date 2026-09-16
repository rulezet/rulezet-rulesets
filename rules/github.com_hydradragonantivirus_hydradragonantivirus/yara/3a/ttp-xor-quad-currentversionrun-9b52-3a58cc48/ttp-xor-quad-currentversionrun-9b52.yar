rule TTP_XOR_QUAD_CurrentVersionRun_9b52 {
  strings:
    $key_9b52 = { c8 3d [2] ec 33 [2] c7 1f [2] e9 3d [2] fd 26 [2] f2 3c [2] ec 21 [2] ee 20 [2] f5 26 [2] e9 21 [2] f5 0e }

  condition:
    any of them
}