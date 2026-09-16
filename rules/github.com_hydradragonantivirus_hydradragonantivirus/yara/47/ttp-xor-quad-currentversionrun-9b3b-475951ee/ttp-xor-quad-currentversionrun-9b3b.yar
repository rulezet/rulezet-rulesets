rule TTP_XOR_QUAD_CurrentVersionRun_9b3b {
  strings:
    $key_9b3b = { c8 54 [2] ec 5a [2] c7 76 [2] e9 54 [2] fd 4f [2] f2 55 [2] ec 48 [2] ee 49 [2] f5 4f [2] e9 48 [2] f5 67 }

  condition:
    any of them
}