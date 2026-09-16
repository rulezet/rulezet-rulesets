rule TTP_XOR_QUAD_CurrentVersionRun_9b29 {
  strings:
    $key_9b29 = { c8 46 [2] ec 48 [2] c7 64 [2] e9 46 [2] fd 5d [2] f2 47 [2] ec 5a [2] ee 5b [2] f5 5d [2] e9 5a [2] f5 75 }

  condition:
    any of them
}