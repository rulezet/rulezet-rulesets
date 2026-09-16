rule TTP_XOR_QUAD_CurrentVersionRun_25de {
  strings:
    $key_25de = { 76 b1 [2] 52 bf [2] 79 93 [2] 57 b1 [2] 43 aa [2] 4c b0 [2] 52 ad [2] 50 ac [2] 4b aa [2] 57 ad [2] 4b 82 }

  condition:
    any of them
}