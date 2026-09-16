rule TTP_XOR_QUAD_CurrentVersionRun_9b1d {
  strings:
    $key_9b1d = { c8 72 [2] ec 7c [2] c7 50 [2] e9 72 [2] fd 69 [2] f2 73 [2] ec 6e [2] ee 6f [2] f5 69 [2] e9 6e [2] f5 41 }

  condition:
    any of them
}