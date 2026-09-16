rule TTP_XOR_QUAD_CurrentVersionRun_a7de {
  strings:
    $key_a7de = { f4 b1 [2] d0 bf [2] fb 93 [2] d5 b1 [2] c1 aa [2] ce b0 [2] d0 ad [2] d2 ac [2] c9 aa [2] d5 ad [2] c9 82 }

  condition:
    any of them
}