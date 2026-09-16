rule TTP_XOR_QUAD_CurrentVersionRun_b5de {
  strings:
    $key_b5de = { e6 b1 [2] c2 bf [2] e9 93 [2] c7 b1 [2] d3 aa [2] dc b0 [2] c2 ad [2] c0 ac [2] db aa [2] c7 ad [2] db 82 }

  condition:
    any of them
}