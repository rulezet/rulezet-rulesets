rule TTP_XOR_QUAD_CurrentVersionRun_87f7 {
  strings:
    $key_87f7 = { d4 98 [2] f0 96 [2] db ba [2] f5 98 [2] e1 83 [2] ee 99 [2] f0 84 [2] f2 85 [2] e9 83 [2] f5 84 [2] e9 ab }

  condition:
    any of them
}