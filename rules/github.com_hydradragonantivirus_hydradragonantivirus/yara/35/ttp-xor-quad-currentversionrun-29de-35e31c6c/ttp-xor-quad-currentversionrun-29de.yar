rule TTP_XOR_QUAD_CurrentVersionRun_29de {
  strings:
    $key_29de = { 7a b1 [2] 5e bf [2] 75 93 [2] 5b b1 [2] 4f aa [2] 40 b0 [2] 5e ad [2] 5c ac [2] 47 aa [2] 5b ad [2] 47 82 }

  condition:
    any of them
}