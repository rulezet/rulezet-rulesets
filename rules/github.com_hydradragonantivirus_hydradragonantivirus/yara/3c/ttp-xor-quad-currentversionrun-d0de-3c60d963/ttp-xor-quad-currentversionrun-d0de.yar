rule TTP_XOR_QUAD_CurrentVersionRun_d0de {
  strings:
    $key_d0de = { 83 b1 [2] a7 bf [2] 8c 93 [2] a2 b1 [2] b6 aa [2] b9 b0 [2] a7 ad [2] a5 ac [2] be aa [2] a2 ad [2] be 82 }

  condition:
    any of them
}