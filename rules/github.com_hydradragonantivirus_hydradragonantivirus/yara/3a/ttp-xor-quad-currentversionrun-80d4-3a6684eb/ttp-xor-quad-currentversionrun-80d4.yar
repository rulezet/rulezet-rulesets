rule TTP_XOR_QUAD_CurrentVersionRun_80d4 {
  strings:
    $key_80d4 = { d3 bb [2] f7 b5 [2] dc 99 [2] f2 bb [2] e6 a0 [2] e9 ba [2] f7 a7 [2] f5 a6 [2] ee a0 [2] f2 a7 [2] ee 88 }

  condition:
    any of them
}