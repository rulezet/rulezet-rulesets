rule TTP_XOR_QUAD_CurrentVersionRun_78de {
  strings:
    $key_78de = { 2b b1 [2] 0f bf [2] 24 93 [2] 0a b1 [2] 1e aa [2] 11 b0 [2] 0f ad [2] 0d ac [2] 16 aa [2] 0a ad [2] 16 82 }

  condition:
    any of them
}