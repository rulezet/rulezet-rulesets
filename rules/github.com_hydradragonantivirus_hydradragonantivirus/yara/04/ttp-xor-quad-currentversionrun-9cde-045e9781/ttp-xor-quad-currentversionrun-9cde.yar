rule TTP_XOR_QUAD_CurrentVersionRun_9cde {
  strings:
    $key_9cde = { cf b1 [2] eb bf [2] c0 93 [2] ee b1 [2] fa aa [2] f5 b0 [2] eb ad [2] e9 ac [2] f2 aa [2] ee ad [2] f2 82 }

  condition:
    any of them
}