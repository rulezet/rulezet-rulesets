rule TTP_XOR_QUAD_CurrentVersionRun_9b7e {
  strings:
    $key_9b7e = { c8 11 [2] ec 1f [2] c7 33 [2] e9 11 [2] fd 0a [2] f2 10 [2] ec 0d [2] ee 0c [2] f5 0a [2] e9 0d [2] f5 22 }

  condition:
    any of them
}