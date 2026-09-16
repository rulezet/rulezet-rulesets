rule TTP_XOR_QUAD_CurrentVersionRun_f1de {
  strings:
    $key_f1de = { a2 b1 [2] 86 bf [2] ad 93 [2] 83 b1 [2] 97 aa [2] 98 b0 [2] 86 ad [2] 84 ac [2] 9f aa [2] 83 ad [2] 9f 82 }

  condition:
    any of them
}