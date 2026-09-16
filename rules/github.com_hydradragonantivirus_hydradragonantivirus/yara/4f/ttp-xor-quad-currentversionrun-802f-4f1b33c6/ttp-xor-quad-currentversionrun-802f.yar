rule TTP_XOR_QUAD_CurrentVersionRun_802f {
  strings:
    $key_802f = { d3 40 [2] f7 4e [2] dc 62 [2] f2 40 [2] e6 5b [2] e9 41 [2] f7 5c [2] f5 5d [2] ee 5b [2] f2 5c [2] ee 73 }

  condition:
    any of them
}