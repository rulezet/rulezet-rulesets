rule TTP_XOR_QUAD_CurrentVersionRun_97de {
  strings:
    $key_97de = { c4 b1 [2] e0 bf [2] cb 93 [2] e5 b1 [2] f1 aa [2] fe b0 [2] e0 ad [2] e2 ac [2] f9 aa [2] e5 ad [2] f9 82 }

  condition:
    any of them
}