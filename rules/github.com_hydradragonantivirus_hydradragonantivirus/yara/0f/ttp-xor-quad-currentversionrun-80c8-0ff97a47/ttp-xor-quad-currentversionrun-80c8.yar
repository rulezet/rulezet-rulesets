rule TTP_XOR_QUAD_CurrentVersionRun_80c8 {
  strings:
    $key_80c8 = { d3 a7 [2] f7 a9 [2] dc 85 [2] f2 a7 [2] e6 bc [2] e9 a6 [2] f7 bb [2] f5 ba [2] ee bc [2] f2 bb [2] ee 94 }

  condition:
    any of them
}