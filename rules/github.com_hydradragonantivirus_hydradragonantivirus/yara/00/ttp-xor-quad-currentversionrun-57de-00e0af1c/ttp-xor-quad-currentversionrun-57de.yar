rule TTP_XOR_QUAD_CurrentVersionRun_57de {
  strings:
    $key_57de = { 04 b1 [2] 20 bf [2] 0b 93 [2] 25 b1 [2] 31 aa [2] 3e b0 [2] 20 ad [2] 22 ac [2] 39 aa [2] 25 ad [2] 39 82 }

  condition:
    any of them
}