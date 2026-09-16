rule TTP_XOR_QUAD_CurrentVersionRun_9b33 {
  strings:
    $key_9b33 = { c8 5c [2] ec 52 [2] c7 7e [2] e9 5c [2] fd 47 [2] f2 5d [2] ec 40 [2] ee 41 [2] f5 47 [2] e9 40 [2] f5 6f }

  condition:
    any of them
}