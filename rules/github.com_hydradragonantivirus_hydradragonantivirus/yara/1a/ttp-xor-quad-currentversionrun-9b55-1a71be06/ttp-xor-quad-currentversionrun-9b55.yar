rule TTP_XOR_QUAD_CurrentVersionRun_9b55 {
  strings:
    $key_9b55 = { c8 3a [2] ec 34 [2] c7 18 [2] e9 3a [2] fd 21 [2] f2 3b [2] ec 26 [2] ee 27 [2] f5 21 [2] e9 26 [2] f5 09 }

  condition:
    any of them
}