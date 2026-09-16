rule TTP_XOR_QUAD_CurrentVersionRun_64de {
  strings:
    $key_64de = { 37 b1 [2] 13 bf [2] 38 93 [2] 16 b1 [2] 02 aa [2] 0d b0 [2] 13 ad [2] 11 ac [2] 0a aa [2] 16 ad [2] 0a 82 }

  condition:
    any of them
}