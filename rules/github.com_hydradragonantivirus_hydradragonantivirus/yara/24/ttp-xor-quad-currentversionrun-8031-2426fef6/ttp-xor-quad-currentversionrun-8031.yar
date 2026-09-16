rule TTP_XOR_QUAD_CurrentVersionRun_8031 {
  strings:
    $key_8031 = { d3 5e [2] f7 50 [2] dc 7c [2] f2 5e [2] e6 45 [2] e9 5f [2] f7 42 [2] f5 43 [2] ee 45 [2] f2 42 [2] ee 6d }

  condition:
    any of them
}