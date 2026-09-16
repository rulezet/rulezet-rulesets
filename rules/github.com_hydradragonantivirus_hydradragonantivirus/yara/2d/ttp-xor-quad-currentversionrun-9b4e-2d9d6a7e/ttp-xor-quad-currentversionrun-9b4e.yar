rule TTP_XOR_QUAD_CurrentVersionRun_9b4e {
  strings:
    $key_9b4e = { c8 21 [2] ec 2f [2] c7 03 [2] e9 21 [2] fd 3a [2] f2 20 [2] ec 3d [2] ee 3c [2] f5 3a [2] e9 3d [2] f5 12 }

  condition:
    any of them
}