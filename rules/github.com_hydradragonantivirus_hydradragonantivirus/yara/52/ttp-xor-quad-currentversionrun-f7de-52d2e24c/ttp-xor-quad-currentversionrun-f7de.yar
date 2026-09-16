rule TTP_XOR_QUAD_CurrentVersionRun_f7de {
  strings:
    $key_f7de = { a4 b1 [2] 80 bf [2] ab 93 [2] 85 b1 [2] 91 aa [2] 9e b0 [2] 80 ad [2] 82 ac [2] 99 aa [2] 85 ad [2] 99 82 }

  condition:
    any of them
}