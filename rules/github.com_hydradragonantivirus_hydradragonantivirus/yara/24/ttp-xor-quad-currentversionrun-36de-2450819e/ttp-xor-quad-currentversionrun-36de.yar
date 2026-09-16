rule TTP_XOR_QUAD_CurrentVersionRun_36de {
  strings:
    $key_36de = { 65 b1 [2] 41 bf [2] 6a 93 [2] 44 b1 [2] 50 aa [2] 5f b0 [2] 41 ad [2] 43 ac [2] 58 aa [2] 44 ad [2] 58 82 }

  condition:
    any of them
}