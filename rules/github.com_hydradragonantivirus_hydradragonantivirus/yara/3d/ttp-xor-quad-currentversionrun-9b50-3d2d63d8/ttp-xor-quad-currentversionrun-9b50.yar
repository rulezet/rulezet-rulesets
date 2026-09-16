rule TTP_XOR_QUAD_CurrentVersionRun_9b50 {
  strings:
    $key_9b50 = { c8 3f [2] ec 31 [2] c7 1d [2] e9 3f [2] fd 24 [2] f2 3e [2] ec 23 [2] ee 22 [2] f5 24 [2] e9 23 [2] f5 0c }

  condition:
    any of them
}