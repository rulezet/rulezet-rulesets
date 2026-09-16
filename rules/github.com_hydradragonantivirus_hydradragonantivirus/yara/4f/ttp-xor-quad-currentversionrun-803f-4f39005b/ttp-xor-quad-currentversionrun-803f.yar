rule TTP_XOR_QUAD_CurrentVersionRun_803f {
  strings:
    $key_803f = { d3 50 [2] f7 5e [2] dc 72 [2] f2 50 [2] e6 4b [2] e9 51 [2] f7 4c [2] f5 4d [2] ee 4b [2] f2 4c [2] ee 63 }

  condition:
    any of them
}