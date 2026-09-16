rule TTP_XOR_QUAD_CurrentVersionRun_8062 {
  strings:
    $key_8062 = { d3 0d [2] f7 03 [2] dc 2f [2] f2 0d [2] e6 16 [2] e9 0c [2] f7 11 [2] f5 10 [2] ee 16 [2] f2 11 [2] ee 3e }

  condition:
    any of them
}