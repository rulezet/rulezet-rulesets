rule TTP_XOR_QUAD_CurrentVersionRun_e2de {
  strings:
    $key_e2de = { b1 b1 [2] 95 bf [2] be 93 [2] 90 b1 [2] 84 aa [2] 8b b0 [2] 95 ad [2] 97 ac [2] 8c aa [2] 90 ad [2] 8c 82 }

  condition:
    any of them
}