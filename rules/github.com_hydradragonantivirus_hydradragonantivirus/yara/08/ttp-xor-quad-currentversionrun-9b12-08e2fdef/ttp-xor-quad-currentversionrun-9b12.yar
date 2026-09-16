rule TTP_XOR_QUAD_CurrentVersionRun_9b12 {
  strings:
    $key_9b12 = { c8 7d [2] ec 73 [2] c7 5f [2] e9 7d [2] fd 66 [2] f2 7c [2] ec 61 [2] ee 60 [2] f5 66 [2] e9 61 [2] f5 4e }

  condition:
    any of them
}