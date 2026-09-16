rule TTP_XOR_QUAD_CurrentVersionRun_99de {
  strings:
    $key_99de = { ca b1 [2] ee bf [2] c5 93 [2] eb b1 [2] ff aa [2] f0 b0 [2] ee ad [2] ec ac [2] f7 aa [2] eb ad [2] f7 82 }

  condition:
    any of them
}