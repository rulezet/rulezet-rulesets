rule TTP_XOR_QUAD_CurrentVersionRun_e5de {
  strings:
    $key_e5de = { b6 b1 [2] 92 bf [2] b9 93 [2] 97 b1 [2] 83 aa [2] 8c b0 [2] 92 ad [2] 90 ac [2] 8b aa [2] 97 ad [2] 8b 82 }

  condition:
    any of them
}