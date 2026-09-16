rule TTP_XOR_QUAD_CurrentVersionRun_f4de {
  strings:
    $key_f4de = { a7 b1 [2] 83 bf [2] a8 93 [2] 86 b1 [2] 92 aa [2] 9d b0 [2] 83 ad [2] 81 ac [2] 9a aa [2] 86 ad [2] 9a 82 }

  condition:
    any of them
}