rule TTP_XOR_QUAD_CurrentVersionRun_51de {
  strings:
    $key_51de = { 02 b1 [2] 26 bf [2] 0d 93 [2] 23 b1 [2] 37 aa [2] 38 b0 [2] 26 ad [2] 24 ac [2] 3f aa [2] 23 ad [2] 3f 82 }

  condition:
    any of them
}