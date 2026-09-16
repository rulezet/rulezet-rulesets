rule TTP_XOR_QUAD_CurrentVersionRun_9b48 {
  strings:
    $key_9b48 = { c8 27 [2] ec 29 [2] c7 05 [2] e9 27 [2] fd 3c [2] f2 26 [2] ec 3b [2] ee 3a [2] f5 3c [2] e9 3b [2] f5 14 }

  condition:
    any of them
}