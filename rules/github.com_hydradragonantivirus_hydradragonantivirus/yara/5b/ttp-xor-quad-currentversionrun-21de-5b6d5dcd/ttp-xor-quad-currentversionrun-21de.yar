rule TTP_XOR_QUAD_CurrentVersionRun_21de {
  strings:
    $key_21de = { 72 b1 [2] 56 bf [2] 7d 93 [2] 53 b1 [2] 47 aa [2] 48 b0 [2] 56 ad [2] 54 ac [2] 4f aa [2] 53 ad [2] 4f 82 }

  condition:
    any of them
}