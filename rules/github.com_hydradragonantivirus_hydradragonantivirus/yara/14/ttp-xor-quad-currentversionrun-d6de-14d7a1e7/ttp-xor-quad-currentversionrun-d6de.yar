rule TTP_XOR_QUAD_CurrentVersionRun_d6de {
  strings:
    $key_d6de = { 85 b1 [2] a1 bf [2] 8a 93 [2] a4 b1 [2] b0 aa [2] bf b0 [2] a1 ad [2] a3 ac [2] b8 aa [2] a4 ad [2] b8 82 }

  condition:
    any of them
}