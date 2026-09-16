rule TTP_XOR_QUAD_CurrentVersionRun_9b18 {
  strings:
    $key_9b18 = { c8 77 [2] ec 79 [2] c7 55 [2] e9 77 [2] fd 6c [2] f2 76 [2] ec 6b [2] ee 6a [2] f5 6c [2] e9 6b [2] f5 44 }

  condition:
    any of them
}