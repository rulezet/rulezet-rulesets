rule TTP_XOR_QUAD_CurrentVersionRun_f0de {
  strings:
    $key_f0de = { a3 b1 [2] 87 bf [2] ac 93 [2] 82 b1 [2] 96 aa [2] 99 b0 [2] 87 ad [2] 85 ac [2] 9e aa [2] 82 ad [2] 9e 82 }

  condition:
    any of them
}