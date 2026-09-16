rule TTP_XOR_QUAD_CurrentVersionRun_32de {
  strings:
    $key_32de = { 61 b1 [2] 45 bf [2] 6e 93 [2] 40 b1 [2] 54 aa [2] 5b b0 [2] 45 ad [2] 47 ac [2] 5c aa [2] 40 ad [2] 5c 82 }

  condition:
    any of them
}