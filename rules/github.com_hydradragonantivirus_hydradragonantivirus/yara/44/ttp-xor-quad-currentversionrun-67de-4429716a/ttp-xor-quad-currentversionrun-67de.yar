rule TTP_XOR_QUAD_CurrentVersionRun_67de {
  strings:
    $key_67de = { 34 b1 [2] 10 bf [2] 3b 93 [2] 15 b1 [2] 01 aa [2] 0e b0 [2] 10 ad [2] 12 ac [2] 09 aa [2] 15 ad [2] 09 82 }

  condition:
    any of them
}