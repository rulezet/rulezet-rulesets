rule TTP_XOR_QUAD_CurrentVersionRun_99a8 {
  strings:
    $key_99a8 = { ca c7 [2] ee c9 [2] c5 e5 [2] eb c7 [2] ff dc [2] f0 c6 [2] ee db [2] ec da [2] f7 dc [2] eb db [2] f7 f4 }

  condition:
    any of them
}