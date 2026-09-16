rule TTP_XOR_QUAD_CurrentVersionRun_80cf {
  strings:
    $key_80cf = { d3 a0 [2] f7 ae [2] dc 82 [2] f2 a0 [2] e6 bb [2] e9 a1 [2] f7 bc [2] f5 bd [2] ee bb [2] f2 bc [2] ee 93 }

  condition:
    any of them
}