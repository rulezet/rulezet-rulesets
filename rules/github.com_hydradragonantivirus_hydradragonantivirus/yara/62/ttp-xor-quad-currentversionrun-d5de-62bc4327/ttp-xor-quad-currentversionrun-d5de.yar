rule TTP_XOR_QUAD_CurrentVersionRun_d5de {
  strings:
    $key_d5de = { 86 b1 [2] a2 bf [2] 89 93 [2] a7 b1 [2] b3 aa [2] bc b0 [2] a2 ad [2] a0 ac [2] bb aa [2] a7 ad [2] bb 82 }

  condition:
    any of them
}