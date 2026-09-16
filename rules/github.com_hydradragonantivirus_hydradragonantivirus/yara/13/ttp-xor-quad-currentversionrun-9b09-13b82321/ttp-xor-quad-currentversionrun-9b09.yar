rule TTP_XOR_QUAD_CurrentVersionRun_9b09 {
  strings:
    $key_9b09 = { c8 66 [2] ec 68 [2] c7 44 [2] e9 66 [2] fd 7d [2] f2 67 [2] ec 7a [2] ee 7b [2] f5 7d [2] e9 7a [2] f5 55 }

  condition:
    any of them
}