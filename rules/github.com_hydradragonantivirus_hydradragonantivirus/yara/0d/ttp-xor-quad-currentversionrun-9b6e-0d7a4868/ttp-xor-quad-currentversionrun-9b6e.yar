rule TTP_XOR_QUAD_CurrentVersionRun_9b6e {
  strings:
    $key_9b6e = { c8 01 [2] ec 0f [2] c7 23 [2] e9 01 [2] fd 1a [2] f2 00 [2] ec 1d [2] ee 1c [2] f5 1a [2] e9 1d [2] f5 32 }

  condition:
    any of them
}