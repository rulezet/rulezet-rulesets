rule TTP_XOR_QUAD_CurrentVersionRun_99d8 {
  strings:
    $key_99d8 = { ca b7 [2] ee b9 [2] c5 95 [2] eb b7 [2] ff ac [2] f0 b6 [2] ee ab [2] ec aa [2] f7 ac [2] eb ab [2] f7 84 }

  condition:
    any of them
}