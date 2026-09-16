rule TTP_XOR_QUAD_CurrentVersionRun_54de {
  strings:
    $key_54de = { 07 b1 [2] 23 bf [2] 08 93 [2] 26 b1 [2] 32 aa [2] 3d b0 [2] 23 ad [2] 21 ac [2] 3a aa [2] 26 ad [2] 3a 82 }

  condition:
    any of them
}