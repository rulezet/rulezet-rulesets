rule TTP_XOR_QUAD_CurrentVersionRun_9b4f {
  strings:
    $key_9b4f = { c8 20 [2] ec 2e [2] c7 02 [2] e9 20 [2] fd 3b [2] f2 21 [2] ec 3c [2] ee 3d [2] f5 3b [2] e9 3c [2] f5 13 }

  condition:
    any of them
}