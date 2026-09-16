rule TTP_XOR_QUAD_CurrentVersionRun_9b41 {
  strings:
    $key_9b41 = { c8 2e [2] ec 20 [2] c7 0c [2] e9 2e [2] fd 35 [2] f2 2f [2] ec 32 [2] ee 33 [2] f5 35 [2] e9 32 [2] f5 1d }

  condition:
    any of them
}