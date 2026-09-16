rule TTP_XOR_QUAD_CurrentVersionRun_b9de {
  strings:
    $key_b9de = { ea b1 [2] ce bf [2] e5 93 [2] cb b1 [2] df aa [2] d0 b0 [2] ce ad [2] cc ac [2] d7 aa [2] cb ad [2] d7 82 }

  condition:
    any of them
}