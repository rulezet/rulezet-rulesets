rule TTP_XOR_QUAD_CurrentVersionRun_80a5 {
  strings:
    $key_80a5 = { d3 ca [2] f7 c4 [2] dc e8 [2] f2 ca [2] e6 d1 [2] e9 cb [2] f7 d6 [2] f5 d7 [2] ee d1 [2] f2 d6 [2] ee f9 }

  condition:
    any of them
}