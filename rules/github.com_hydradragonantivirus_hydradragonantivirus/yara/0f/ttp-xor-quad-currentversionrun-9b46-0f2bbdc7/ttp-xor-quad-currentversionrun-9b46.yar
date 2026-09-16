rule TTP_XOR_QUAD_CurrentVersionRun_9b46 {
  strings:
    $key_9b46 = { c8 29 [2] ec 27 [2] c7 0b [2] e9 29 [2] fd 32 [2] f2 28 [2] ec 35 [2] ee 34 [2] f5 32 [2] e9 35 [2] f5 1a }

  condition:
    any of them
}