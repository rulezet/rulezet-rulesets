rule TTP_XOR_QUAD_CurrentVersionRun_39de {
  strings:
    $key_39de = { 6a b1 [2] 4e bf [2] 65 93 [2] 4b b1 [2] 5f aa [2] 50 b0 [2] 4e ad [2] 4c ac [2] 57 aa [2] 4b ad [2] 57 82 }

  condition:
    any of them
}