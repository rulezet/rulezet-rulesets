rule TTP_XOR_QUAD_CurrentVersionRun_9b5b {
  strings:
    $key_9b5b = { c8 34 [2] ec 3a [2] c7 16 [2] e9 34 [2] fd 2f [2] f2 35 [2] ec 28 [2] ee 29 [2] f5 2f [2] e9 28 [2] f5 07 }

  condition:
    any of them
}