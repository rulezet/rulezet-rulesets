rule TTP_XOR_QUAD_CurrentVersionRun_87f0 {
  strings:
    $key_87f0 = { d4 9f [2] f0 91 [2] db bd [2] f5 9f [2] e1 84 [2] ee 9e [2] f0 83 [2] f2 82 [2] e9 84 [2] f5 83 [2] e9 ac }

  condition:
    any of them
}