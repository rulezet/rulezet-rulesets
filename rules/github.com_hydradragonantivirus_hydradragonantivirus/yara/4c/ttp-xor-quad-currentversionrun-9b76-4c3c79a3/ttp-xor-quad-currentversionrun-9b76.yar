rule TTP_XOR_QUAD_CurrentVersionRun_9b76 {
  strings:
    $key_9b76 = { c8 19 [2] ec 17 [2] c7 3b [2] e9 19 [2] fd 02 [2] f2 18 [2] ec 05 [2] ee 04 [2] f5 02 [2] e9 05 [2] f5 2a }

  condition:
    any of them
}