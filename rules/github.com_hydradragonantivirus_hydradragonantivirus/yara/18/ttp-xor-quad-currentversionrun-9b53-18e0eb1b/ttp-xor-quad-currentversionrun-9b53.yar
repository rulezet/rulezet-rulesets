rule TTP_XOR_QUAD_CurrentVersionRun_9b53 {
  strings:
    $key_9b53 = { c8 3c [2] ec 32 [2] c7 1e [2] e9 3c [2] fd 27 [2] f2 3d [2] ec 20 [2] ee 21 [2] f5 27 [2] e9 20 [2] f5 0f }

  condition:
    any of them
}