rule TTP_XOR_QUAD_CurrentVersionRun_800f {
  strings:
    $key_800f = { d3 60 [2] f7 6e [2] dc 42 [2] f2 60 [2] e6 7b [2] e9 61 [2] f7 7c [2] f5 7d [2] ee 7b [2] f2 7c [2] ee 53 }

  condition:
    any of them
}