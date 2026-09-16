rule TTP_XOR_QUAD_CurrentVersionRun_59de {
  strings:
    $key_59de = { 0a b1 [2] 2e bf [2] 05 93 [2] 2b b1 [2] 3f aa [2] 30 b0 [2] 2e ad [2] 2c ac [2] 37 aa [2] 2b ad [2] 37 82 }

  condition:
    any of them
}