rule TTP_XOR_QUAD_CurrentVersionRun_807e {
  strings:
    $key_807e = { d3 11 [2] f7 1f [2] dc 33 [2] f2 11 [2] e6 0a [2] e9 10 [2] f7 0d [2] f5 0c [2] ee 0a [2] f2 0d [2] ee 22 }

  condition:
    any of them
}