rule TTP_XOR_QUAD_CurrentVersionRun_87e2 {
  strings:
    $key_87e2 = { d4 8d [2] f0 83 [2] db af [2] f5 8d [2] e1 96 [2] ee 8c [2] f0 91 [2] f2 90 [2] e9 96 [2] f5 91 [2] e9 be }

  condition:
    any of them
}