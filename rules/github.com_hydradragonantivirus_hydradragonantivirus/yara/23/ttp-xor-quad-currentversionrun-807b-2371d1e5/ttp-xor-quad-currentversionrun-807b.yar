rule TTP_XOR_QUAD_CurrentVersionRun_807b {
  strings:
    $key_807b = { d3 14 [2] f7 1a [2] dc 36 [2] f2 14 [2] e6 0f [2] e9 15 [2] f7 08 [2] f5 09 [2] ee 0f [2] f2 08 [2] ee 27 }

  condition:
    any of them
}