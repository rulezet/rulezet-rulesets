rule TTP_XOR_QUAD_CurrentVersionRun_9bef {
  strings:
    $key_9bef = { c8 80 [2] ec 8e [2] c7 a2 [2] e9 80 [2] fd 9b [2] f2 81 [2] ec 9c [2] ee 9d [2] f5 9b [2] e9 9c [2] f5 b3 }

  condition:
    any of them
}