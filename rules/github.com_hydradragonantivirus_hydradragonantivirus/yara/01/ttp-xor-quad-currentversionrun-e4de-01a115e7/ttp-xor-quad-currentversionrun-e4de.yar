rule TTP_XOR_QUAD_CurrentVersionRun_e4de {
  strings:
    $key_e4de = { b7 b1 [2] 93 bf [2] b8 93 [2] 96 b1 [2] 82 aa [2] 8d b0 [2] 93 ad [2] 91 ac [2] 8a aa [2] 96 ad [2] 8a 82 }

  condition:
    any of them
}