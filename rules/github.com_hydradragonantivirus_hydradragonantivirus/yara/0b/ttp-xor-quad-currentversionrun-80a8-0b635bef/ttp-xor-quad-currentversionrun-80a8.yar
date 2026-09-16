rule TTP_XOR_QUAD_CurrentVersionRun_80a8 {
  strings:
    $key_80a8 = { d3 c7 [2] f7 c9 [2] dc e5 [2] f2 c7 [2] e6 dc [2] e9 c6 [2] f7 db [2] f5 da [2] ee dc [2] f2 db [2] ee f4 }

  condition:
    any of them
}