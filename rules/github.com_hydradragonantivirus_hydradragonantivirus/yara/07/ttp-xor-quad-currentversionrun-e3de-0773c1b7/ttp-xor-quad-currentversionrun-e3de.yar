rule TTP_XOR_QUAD_CurrentVersionRun_e3de {
  strings:
    $key_e3de = { b0 b1 [2] 94 bf [2] bf 93 [2] 91 b1 [2] 85 aa [2] 8a b0 [2] 94 ad [2] 96 ac [2] 8d aa [2] 91 ad [2] 8d 82 }

  condition:
    any of them
}