rule TTP_XOR_QUAD_CurrentVersionRun_46de {
  strings:
    $key_46de = { 15 b1 [2] 31 bf [2] 1a 93 [2] 34 b1 [2] 20 aa [2] 2f b0 [2] 31 ad [2] 33 ac [2] 28 aa [2] 34 ad [2] 28 82 }

  condition:
    any of them
}