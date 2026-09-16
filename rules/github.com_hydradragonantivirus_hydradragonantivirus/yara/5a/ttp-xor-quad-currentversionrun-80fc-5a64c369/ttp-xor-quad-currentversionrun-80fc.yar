rule TTP_XOR_QUAD_CurrentVersionRun_80fc {
  strings:
    $key_80fc = { d3 93 [2] f7 9d [2] dc b1 [2] f2 93 [2] e6 88 [2] e9 92 [2] f7 8f [2] f5 8e [2] ee 88 [2] f2 8f [2] ee a0 }

  condition:
    any of them
}