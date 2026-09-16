rule TTP_XOR_QUAD_CurrentVersionRun_802a {
  strings:
    $key_802a = { d3 45 [2] f7 4b [2] dc 67 [2] f2 45 [2] e6 5e [2] e9 44 [2] f7 59 [2] f5 58 [2] ee 5e [2] f2 59 [2] ee 76 }

  condition:
    any of them
}