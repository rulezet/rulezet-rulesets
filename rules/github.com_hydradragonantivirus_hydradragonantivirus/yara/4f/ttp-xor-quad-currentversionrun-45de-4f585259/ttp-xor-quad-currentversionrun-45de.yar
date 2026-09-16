rule TTP_XOR_QUAD_CurrentVersionRun_45de {
  strings:
    $key_45de = { 16 b1 [2] 32 bf [2] 19 93 [2] 37 b1 [2] 23 aa [2] 2c b0 [2] 32 ad [2] 30 ac [2] 2b aa [2] 37 ad [2] 2b 82 }

  condition:
    any of them
}