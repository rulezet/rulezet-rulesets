rule TTP_XOR_QUAD_CurrentVersionRun_9953 {
  strings:
    $key_9953 = { ca 3c [2] ee 32 [2] c5 1e [2] eb 3c [2] ff 27 [2] f0 3d [2] ee 20 [2] ec 21 [2] f7 27 [2] eb 20 [2] f7 0f }

  condition:
    any of them
}