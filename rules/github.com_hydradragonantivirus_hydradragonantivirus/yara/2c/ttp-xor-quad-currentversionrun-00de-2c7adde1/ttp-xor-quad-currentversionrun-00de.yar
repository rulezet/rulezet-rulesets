rule TTP_XOR_QUAD_CurrentVersionRun_00de {
  strings:
    $key_00de = { 53 b1 [2] 77 bf [2] 5c 93 [2] 72 b1 [2] 66 aa [2] 69 b0 [2] 77 ad [2] 75 ac [2] 6e aa [2] 72 ad [2] 6e 82 }

  condition:
    any of them
}