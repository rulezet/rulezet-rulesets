rule TTP_XOR_QUAD_CurrentVersionRun_80d7 {
  strings:
    $key_80d7 = { d3 b8 [2] f7 b6 [2] dc 9a [2] f2 b8 [2] e6 a3 [2] e9 b9 [2] f7 a4 [2] f5 a5 [2] ee a3 [2] f2 a4 [2] ee 8b }

  condition:
    any of them
}