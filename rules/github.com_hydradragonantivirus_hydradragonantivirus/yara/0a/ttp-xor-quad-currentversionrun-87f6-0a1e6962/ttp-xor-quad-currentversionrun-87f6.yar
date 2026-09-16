rule TTP_XOR_QUAD_CurrentVersionRun_87f6 {
  strings:
    $key_87f6 = { d4 99 [2] f0 97 [2] db bb [2] f5 99 [2] e1 82 [2] ee 98 [2] f0 85 [2] f2 84 [2] e9 82 [2] f5 85 [2] e9 aa }

  condition:
    any of them
}