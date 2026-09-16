rule TTP_XOR_QUAD_CurrentVersionRun_9b68 {
  strings:
    $key_9b68 = { c8 07 [2] ec 09 [2] c7 25 [2] e9 07 [2] fd 1c [2] f2 06 [2] ec 1b [2] ee 1a [2] f5 1c [2] e9 1b [2] f5 34 }

  condition:
    any of them
}