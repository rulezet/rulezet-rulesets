rule TTP_XOR_QUAD_CurrentVersionRun_802e {
  strings:
    $key_802e = { d3 41 [2] f7 4f [2] dc 63 [2] f2 41 [2] e6 5a [2] e9 40 [2] f7 5d [2] f5 5c [2] ee 5a [2] f2 5d [2] ee 72 }

  condition:
    any of them
}