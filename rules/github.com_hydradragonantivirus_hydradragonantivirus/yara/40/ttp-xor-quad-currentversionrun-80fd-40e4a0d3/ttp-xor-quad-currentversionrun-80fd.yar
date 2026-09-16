rule TTP_XOR_QUAD_CurrentVersionRun_80fd {
  strings:
    $key_80fd = { d3 92 [2] f7 9c [2] dc b0 [2] f2 92 [2] e6 89 [2] e9 93 [2] f7 8e [2] f5 8f [2] ee 89 [2] f2 8e [2] ee a1 }

  condition:
    any of them
}