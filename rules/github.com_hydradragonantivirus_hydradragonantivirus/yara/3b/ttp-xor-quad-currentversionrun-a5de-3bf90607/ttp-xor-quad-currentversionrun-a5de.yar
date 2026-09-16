rule TTP_XOR_QUAD_CurrentVersionRun_a5de {
  strings:
    $key_a5de = { f6 b1 [2] d2 bf [2] f9 93 [2] d7 b1 [2] c3 aa [2] cc b0 [2] d2 ad [2] d0 ac [2] cb aa [2] d7 ad [2] cb 82 }

  condition:
    any of them
}