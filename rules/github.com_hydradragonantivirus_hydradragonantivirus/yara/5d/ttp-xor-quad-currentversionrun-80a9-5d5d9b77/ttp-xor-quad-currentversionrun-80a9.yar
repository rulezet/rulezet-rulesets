rule TTP_XOR_QUAD_CurrentVersionRun_80a9 {
  strings:
    $key_80a9 = { d3 c6 [2] f7 c8 [2] dc e4 [2] f2 c6 [2] e6 dd [2] e9 c7 [2] f7 da [2] f5 db [2] ee dd [2] f2 da [2] ee f5 }

  condition:
    any of them
}