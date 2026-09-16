rule TTP_XOR_QUAD_CurrentVersionRun_8753 {
  strings:
    $key_8753 = { d4 3c [2] f0 32 [2] db 1e [2] f5 3c [2] e1 27 [2] ee 3d [2] f0 20 [2] f2 21 [2] e9 27 [2] f5 20 [2] e9 0f }

  condition:
    any of them
}