rule TTP_XOR_QUAD_CurrentVersionRun_9b08 {
  strings:
    $key_9b08 = { c8 67 [2] ec 69 [2] c7 45 [2] e9 67 [2] fd 7c [2] f2 66 [2] ec 7b [2] ee 7a [2] f5 7c [2] e9 7b [2] f5 54 }

  condition:
    any of them
}