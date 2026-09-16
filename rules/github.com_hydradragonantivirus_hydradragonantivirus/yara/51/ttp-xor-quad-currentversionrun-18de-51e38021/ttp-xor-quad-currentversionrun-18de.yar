rule TTP_XOR_QUAD_CurrentVersionRun_18de {
  strings:
    $key_18de = { 4b b1 [2] 6f bf [2] 44 93 [2] 6a b1 [2] 7e aa [2] 71 b0 [2] 6f ad [2] 6d ac [2] 76 aa [2] 6a ad [2] 76 82 }

  condition:
    any of them
}