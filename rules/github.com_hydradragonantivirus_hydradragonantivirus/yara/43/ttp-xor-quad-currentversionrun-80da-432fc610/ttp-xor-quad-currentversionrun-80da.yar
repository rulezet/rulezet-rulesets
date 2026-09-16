rule TTP_XOR_QUAD_CurrentVersionRun_80da {
  strings:
    $key_80da = { d3 b5 [2] f7 bb [2] dc 97 [2] f2 b5 [2] e6 ae [2] e9 b4 [2] f7 a9 [2] f5 a8 [2] ee ae [2] f2 a9 [2] ee 86 }

  condition:
    any of them
}