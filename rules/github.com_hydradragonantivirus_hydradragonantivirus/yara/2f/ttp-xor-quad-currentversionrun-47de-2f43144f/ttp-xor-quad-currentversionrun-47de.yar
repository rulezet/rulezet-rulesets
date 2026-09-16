rule TTP_XOR_QUAD_CurrentVersionRun_47de {
  strings:
    $key_47de = { 14 b1 [2] 30 bf [2] 1b 93 [2] 35 b1 [2] 21 aa [2] 2e b0 [2] 30 ad [2] 32 ac [2] 29 aa [2] 35 ad [2] 29 82 }

  condition:
    any of them
}