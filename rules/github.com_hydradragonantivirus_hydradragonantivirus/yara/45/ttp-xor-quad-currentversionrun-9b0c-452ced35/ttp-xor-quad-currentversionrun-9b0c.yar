rule TTP_XOR_QUAD_CurrentVersionRun_9b0c {
  strings:
    $key_9b0c = { c8 63 [2] ec 6d [2] c7 41 [2] e9 63 [2] fd 78 [2] f2 62 [2] ec 7f [2] ee 7e [2] f5 78 [2] e9 7f [2] f5 50 }

  condition:
    any of them
}