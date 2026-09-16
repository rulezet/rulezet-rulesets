rule TTP_XOR_QUAD_CurrentVersionRun_80e1 {
  strings:
    $key_80e1 = { d3 8e [2] f7 80 [2] dc ac [2] f2 8e [2] e6 95 [2] e9 8f [2] f7 92 [2] f5 93 [2] ee 95 [2] f2 92 [2] ee bd }

  condition:
    any of them
}