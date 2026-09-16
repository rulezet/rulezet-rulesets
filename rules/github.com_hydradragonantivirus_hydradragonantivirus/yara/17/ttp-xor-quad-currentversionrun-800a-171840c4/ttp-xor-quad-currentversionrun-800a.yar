rule TTP_XOR_QUAD_CurrentVersionRun_800a {
  strings:
    $key_800a = { d3 65 [2] f7 6b [2] dc 47 [2] f2 65 [2] e6 7e [2] e9 64 [2] f7 79 [2] f5 78 [2] ee 7e [2] f2 79 [2] ee 56 }

  condition:
    any of them
}