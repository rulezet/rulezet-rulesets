rule TTP_XOR_QUAD_CurrentVersionRun_801c {
  strings:
    $key_801c = { d3 73 [2] f7 7d [2] dc 51 [2] f2 73 [2] e6 68 [2] e9 72 [2] f7 6f [2] f5 6e [2] ee 68 [2] f2 6f [2] ee 40 }

  condition:
    any of them
}