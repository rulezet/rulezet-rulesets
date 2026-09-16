rule TTP_XOR_QUAD_CurrentVersionRun_82de {
  strings:
    $key_82de = { d1 b1 [2] f5 bf [2] de 93 [2] f0 b1 [2] e4 aa [2] eb b0 [2] f5 ad [2] f7 ac [2] ec aa [2] f0 ad [2] ec 82 }

  condition:
    any of them
}