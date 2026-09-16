rule TTP_XOR_QUAD_CurrentVersionRun_9b1e {
  strings:
    $key_9b1e = { c8 71 [2] ec 7f [2] c7 53 [2] e9 71 [2] fd 6a [2] f2 70 [2] ec 6d [2] ee 6c [2] f5 6a [2] e9 6d [2] f5 42 }

  condition:
    any of them
}