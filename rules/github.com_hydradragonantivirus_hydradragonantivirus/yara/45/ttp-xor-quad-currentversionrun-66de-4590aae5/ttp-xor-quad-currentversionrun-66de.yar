rule TTP_XOR_QUAD_CurrentVersionRun_66de {
  strings:
    $key_66de = { 35 b1 [2] 11 bf [2] 3a 93 [2] 14 b1 [2] 00 aa [2] 0f b0 [2] 11 ad [2] 13 ac [2] 08 aa [2] 14 ad [2] 08 82 }

  condition:
    any of them
}