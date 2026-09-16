rule TTP_XOR_QUAD_CurrentVersionRun_62de {
  strings:
    $key_62de = { 31 b1 [2] 15 bf [2] 3e 93 [2] 10 b1 [2] 04 aa [2] 0b b0 [2] 15 ad [2] 17 ac [2] 0c aa [2] 10 ad [2] 0c 82 }

  condition:
    any of them
}