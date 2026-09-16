rule TTP_XOR_QUAD_CurrentVersionRun_8000 {
  strings:
    $key_8000 = { d3 6f [2] f7 61 [2] dc 4d [2] f2 6f [2] e6 74 [2] e9 6e [2] f7 73 [2] f5 72 [2] ee 74 [2] f2 73 [2] ee 5c }

  condition:
    any of them
}