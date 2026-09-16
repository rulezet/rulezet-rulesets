rule TTP_XOR_QUAD_CurrentVersionRun_9b57 {
  strings:
    $key_9b57 = { c8 38 [2] ec 36 [2] c7 1a [2] e9 38 [2] fd 23 [2] f2 39 [2] ec 24 [2] ee 25 [2] f5 23 [2] e9 24 [2] f5 0b }

  condition:
    any of them
}