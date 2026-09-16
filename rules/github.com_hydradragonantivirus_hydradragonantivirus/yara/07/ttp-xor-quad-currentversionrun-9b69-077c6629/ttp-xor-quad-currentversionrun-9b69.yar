rule TTP_XOR_QUAD_CurrentVersionRun_9b69 {
  strings:
    $key_9b69 = { c8 06 [2] ec 08 [2] c7 24 [2] e9 06 [2] fd 1d [2] f2 07 [2] ec 1a [2] ee 1b [2] f5 1d [2] e9 1a [2] f5 35 }

  condition:
    any of them
}