rule TTP_XOR_QUAD_CurrentVersionRun_9b07 {
  strings:
    $key_9b07 = { c8 68 [2] ec 66 [2] c7 4a [2] e9 68 [2] fd 73 [2] f2 69 [2] ec 74 [2] ee 75 [2] f5 73 [2] e9 74 [2] f5 5b }

  condition:
    any of them
}