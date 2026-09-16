rule TTP_XOR_QUAD_CurrentVersionRun_20de {
  strings:
    $key_20de = { 73 b1 [2] 57 bf [2] 7c 93 [2] 52 b1 [2] 46 aa [2] 49 b0 [2] 57 ad [2] 55 ac [2] 4e aa [2] 52 ad [2] 4e 82 }

  condition:
    any of them
}