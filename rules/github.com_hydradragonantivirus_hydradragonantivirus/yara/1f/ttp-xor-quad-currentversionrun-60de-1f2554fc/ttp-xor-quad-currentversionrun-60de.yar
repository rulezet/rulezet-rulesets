rule TTP_XOR_QUAD_CurrentVersionRun_60de {
  strings:
    $key_60de = { 33 b1 [2] 17 bf [2] 3c 93 [2] 12 b1 [2] 06 aa [2] 09 b0 [2] 17 ad [2] 15 ac [2] 0e aa [2] 12 ad [2] 0e 82 }

  condition:
    any of them
}