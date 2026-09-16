rule TTP_XOR_QUAD_CurrentVersionRun_f3de {
  strings:
    $key_f3de = { a0 b1 [2] 84 bf [2] af 93 [2] 81 b1 [2] 95 aa [2] 9a b0 [2] 84 ad [2] 86 ac [2] 9d aa [2] 81 ad [2] 9d 82 }

  condition:
    any of them
}