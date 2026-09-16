rule TTP_XOR_QUAD_CurrentVersionRun_9b7a {
  strings:
    $key_9b7a = { c8 15 [2] ec 1b [2] c7 37 [2] e9 15 [2] fd 0e [2] f2 14 [2] ec 09 [2] ee 08 [2] f5 0e [2] e9 09 [2] f5 26 }

  condition:
    any of them
}