rule TTP_XOR_QUAD_CurrentVersionRun_e9de {
  strings:
    $key_e9de = { ba b1 [2] 9e bf [2] b5 93 [2] 9b b1 [2] 8f aa [2] 80 b0 [2] 9e ad [2] 9c ac [2] 87 aa [2] 9b ad [2] 87 82 }

  condition:
    any of them
}