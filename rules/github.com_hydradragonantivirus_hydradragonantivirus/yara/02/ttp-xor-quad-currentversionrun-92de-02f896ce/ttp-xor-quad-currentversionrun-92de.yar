rule TTP_XOR_QUAD_CurrentVersionRun_92de {
  strings:
    $key_92de = { c1 b1 [2] e5 bf [2] ce 93 [2] e0 b1 [2] f4 aa [2] fb b0 [2] e5 ad [2] e7 ac [2] fc aa [2] e0 ad [2] fc 82 }

  condition:
    any of them
}