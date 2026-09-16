rule TTP_XOR_QUAD_CurrentVersionRun_02de {
  strings:
    $key_02de = { 51 b1 [2] 75 bf [2] 5e 93 [2] 70 b1 [2] 64 aa [2] 6b b0 [2] 75 ad [2] 77 ac [2] 6c aa [2] 70 ad [2] 6c 82 }

  condition:
    any of them
}