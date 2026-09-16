rule TTP_XOR_QUAD_CurrentVersionRun_22de {
  strings:
    $key_22de = { 71 b1 [2] 55 bf [2] 7e 93 [2] 50 b1 [2] 44 aa [2] 4b b0 [2] 55 ad [2] 57 ac [2] 4c aa [2] 50 ad [2] 4c 82 }

  condition:
    any of them
}