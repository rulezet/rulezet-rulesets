rule TTP_XOR_QUAD_CurrentVersionRun_04de {
  strings:
    $key_04de = { 57 b1 [2] 73 bf [2] 58 93 [2] 76 b1 [2] 62 aa [2] 6d b0 [2] 73 ad [2] 71 ac [2] 6a aa [2] 76 ad [2] 6a 82 }

  condition:
    any of them
}