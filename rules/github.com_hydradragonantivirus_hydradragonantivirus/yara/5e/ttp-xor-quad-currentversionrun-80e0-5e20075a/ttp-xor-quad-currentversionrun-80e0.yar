rule TTP_XOR_QUAD_CurrentVersionRun_80e0 {
  strings:
    $key_80e0 = { d3 8f [2] f7 81 [2] dc ad [2] f2 8f [2] e6 94 [2] e9 8e [2] f7 93 [2] f5 92 [2] ee 94 [2] f2 93 [2] ee bc }

  condition:
    any of them
}