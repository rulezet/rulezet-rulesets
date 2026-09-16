rule TTP_XOR_QUAD_CurrentVersionRun_9b73 {
  strings:
    $key_9b73 = { c8 1c [2] ec 12 [2] c7 3e [2] e9 1c [2] fd 07 [2] f2 1d [2] ec 00 [2] ee 01 [2] f5 07 [2] e9 00 [2] f5 2f }

  condition:
    any of them
}