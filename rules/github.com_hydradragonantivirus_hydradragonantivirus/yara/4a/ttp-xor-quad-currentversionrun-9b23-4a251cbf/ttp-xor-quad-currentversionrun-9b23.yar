rule TTP_XOR_QUAD_CurrentVersionRun_9b23 {
  strings:
    $key_9b23 = { c8 4c [2] ec 42 [2] c7 6e [2] e9 4c [2] fd 57 [2] f2 4d [2] ec 50 [2] ee 51 [2] f5 57 [2] e9 50 [2] f5 7f }

  condition:
    any of them
}