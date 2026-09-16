rule TTP_XOR_QUAD_CurrentVersionRun_c2de {
  strings:
    $key_c2de = { 91 b1 [2] b5 bf [2] 9e 93 [2] b0 b1 [2] a4 aa [2] ab b0 [2] b5 ad [2] b7 ac [2] ac aa [2] b0 ad [2] ac 82 }

  condition:
    any of them
}