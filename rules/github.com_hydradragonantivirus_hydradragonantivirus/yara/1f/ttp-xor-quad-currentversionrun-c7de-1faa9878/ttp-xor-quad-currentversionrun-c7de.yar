rule TTP_XOR_QUAD_CurrentVersionRun_c7de {
  strings:
    $key_c7de = { 94 b1 [2] b0 bf [2] 9b 93 [2] b5 b1 [2] a1 aa [2] ae b0 [2] b0 ad [2] b2 ac [2] a9 aa [2] b5 ad [2] a9 82 }

  condition:
    any of them
}