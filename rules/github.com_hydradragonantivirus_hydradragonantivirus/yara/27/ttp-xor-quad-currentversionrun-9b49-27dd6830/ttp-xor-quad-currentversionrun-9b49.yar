rule TTP_XOR_QUAD_CurrentVersionRun_9b49 {
  strings:
    $key_9b49 = { c8 26 [2] ec 28 [2] c7 04 [2] e9 26 [2] fd 3d [2] f2 27 [2] ec 3a [2] ee 3b [2] f5 3d [2] e9 3a [2] f5 15 }

  condition:
    any of them
}