rule TTP_XOR_QUAD_CurrentVersionRun_9bf7 {
  strings:
    $key_9bf7 = { c8 98 [2] ec 96 [2] c7 ba [2] e9 98 [2] fd 83 [2] f2 99 [2] ec 84 [2] ee 85 [2] f5 83 [2] e9 84 [2] f5 ab }

  condition:
    any of them
}