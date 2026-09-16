rule TTP_XOR_QUAD_CurrentVersionRun_8702 {
  strings:
    $key_8702 = { d4 6d [2] f0 63 [2] db 4f [2] f5 6d [2] e1 76 [2] ee 6c [2] f0 71 [2] f2 70 [2] e9 76 [2] f5 71 [2] e9 5e }

  condition:
    any of them
}