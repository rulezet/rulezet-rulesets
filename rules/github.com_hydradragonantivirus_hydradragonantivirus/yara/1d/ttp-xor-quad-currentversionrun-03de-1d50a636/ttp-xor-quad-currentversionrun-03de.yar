rule TTP_XOR_QUAD_CurrentVersionRun_03de {
  strings:
    $key_03de = { 50 b1 [2] 74 bf [2] 5f 93 [2] 71 b1 [2] 65 aa [2] 6a b0 [2] 74 ad [2] 76 ac [2] 6d aa [2] 71 ad [2] 6d 82 }

  condition:
    any of them
}