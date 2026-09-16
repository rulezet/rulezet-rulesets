rule TTP_XOR_QUAD_CurrentVersionRun_30de {
  strings:
    $key_30de = { 63 b1 [2] 47 bf [2] 6c 93 [2] 42 b1 [2] 56 aa [2] 59 b0 [2] 47 ad [2] 45 ac [2] 5e aa [2] 42 ad [2] 5e 82 }

  condition:
    any of them
}