rule TTP_XOR_QUAD_CurrentVersionRun_b0de {
  strings:
    $key_b0de = { e3 b1 [2] c7 bf [2] ec 93 [2] c2 b1 [2] d6 aa [2] d9 b0 [2] c7 ad [2] c5 ac [2] de aa [2] c2 ad [2] de 82 }

  condition:
    any of them
}