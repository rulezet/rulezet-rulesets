rule TTP_XOR_QUAD_CurrentVersionRun_80dd {
  strings:
    $key_80dd = { d3 b2 [2] f7 bc [2] dc 90 [2] f2 b2 [2] e6 a9 [2] e9 b3 [2] f7 ae [2] f5 af [2] ee a9 [2] f2 ae [2] ee 81 }

  condition:
    any of them
}