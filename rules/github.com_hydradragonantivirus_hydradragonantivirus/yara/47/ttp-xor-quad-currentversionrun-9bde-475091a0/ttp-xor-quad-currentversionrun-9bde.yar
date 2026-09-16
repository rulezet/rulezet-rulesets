rule TTP_XOR_QUAD_CurrentVersionRun_9bde {
  strings:
    $key_9bde = { c8 b1 [2] ec bf [2] c7 93 [2] e9 b1 [2] fd aa [2] f2 b0 [2] ec ad [2] ee ac [2] f5 aa [2] e9 ad [2] f5 82 }

  condition:
    any of them
}