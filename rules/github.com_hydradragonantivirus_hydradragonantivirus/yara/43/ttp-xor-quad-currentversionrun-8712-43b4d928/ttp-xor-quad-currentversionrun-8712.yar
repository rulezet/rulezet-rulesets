rule TTP_XOR_QUAD_CurrentVersionRun_8712 {
  strings:
    $key_8712 = { d4 7d [2] f0 73 [2] db 5f [2] f5 7d [2] e1 66 [2] ee 7c [2] f0 61 [2] f2 60 [2] e9 66 [2] f5 61 [2] e9 4e }

  condition:
    any of them
}