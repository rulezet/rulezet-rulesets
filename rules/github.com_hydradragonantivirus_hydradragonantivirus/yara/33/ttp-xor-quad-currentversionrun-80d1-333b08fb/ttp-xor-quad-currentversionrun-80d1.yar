rule TTP_XOR_QUAD_CurrentVersionRun_80d1 {
  strings:
    $key_80d1 = { d3 be [2] f7 b0 [2] dc 9c [2] f2 be [2] e6 a5 [2] e9 bf [2] f7 a2 [2] f5 a3 [2] ee a5 [2] f2 a2 [2] ee 8d }

  condition:
    any of them
}