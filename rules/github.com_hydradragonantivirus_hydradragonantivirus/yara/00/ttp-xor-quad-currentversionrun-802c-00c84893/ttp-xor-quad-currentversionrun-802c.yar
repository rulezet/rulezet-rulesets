rule TTP_XOR_QUAD_CurrentVersionRun_802c {
  strings:
    $key_802c = { d3 43 [2] f7 4d [2] dc 61 [2] f2 43 [2] e6 58 [2] e9 42 [2] f7 5f [2] f5 5e [2] ee 58 [2] f2 5f [2] ee 70 }

  condition:
    any of them
}