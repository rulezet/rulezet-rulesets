rule TTP_XOR_QUAD_CurrentVersionRun_9b28 {
  strings:
    $key_9b28 = { c8 47 [2] ec 49 [2] c7 65 [2] e9 47 [2] fd 5c [2] f2 46 [2] ec 5b [2] ee 5a [2] f5 5c [2] e9 5b [2] f5 74 }

  condition:
    any of them
}