rule TTP_XOR_QUAD_CurrentVersionRun_806b {
  strings:
    $key_806b = { d3 04 [2] f7 0a [2] dc 26 [2] f2 04 [2] e6 1f [2] e9 05 [2] f7 18 [2] f5 19 [2] ee 1f [2] f2 18 [2] ee 37 }

  condition:
    any of them
}