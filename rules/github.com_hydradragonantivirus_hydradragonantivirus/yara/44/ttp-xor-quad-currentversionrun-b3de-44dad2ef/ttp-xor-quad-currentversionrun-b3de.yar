rule TTP_XOR_QUAD_CurrentVersionRun_b3de {
  strings:
    $key_b3de = { e0 b1 [2] c4 bf [2] ef 93 [2] c1 b1 [2] d5 aa [2] da b0 [2] c4 ad [2] c6 ac [2] dd aa [2] c1 ad [2] dd 82 }

  condition:
    any of them
}