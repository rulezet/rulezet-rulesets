rule TTP_XOR_QUAD_CurrentVersionRun_65de {
  strings:
    $key_65de = { 36 b1 [2] 12 bf [2] 39 93 [2] 17 b1 [2] 03 aa [2] 0c b0 [2] 12 ad [2] 10 ac [2] 0b aa [2] 17 ad [2] 0b 82 }

  condition:
    any of them
}