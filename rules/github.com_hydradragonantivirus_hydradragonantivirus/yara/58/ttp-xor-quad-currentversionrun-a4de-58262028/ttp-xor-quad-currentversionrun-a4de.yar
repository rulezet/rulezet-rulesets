rule TTP_XOR_QUAD_CurrentVersionRun_a4de {
  strings:
    $key_a4de = { f7 b1 [2] d3 bf [2] f8 93 [2] d6 b1 [2] c2 aa [2] cd b0 [2] d3 ad [2] d1 ac [2] ca aa [2] d6 ad [2] ca 82 }

  condition:
    any of them
}