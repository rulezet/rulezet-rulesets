rule TTP_XOR_QUAD_CurrentVersionRun_f8de {
  strings:
    $key_f8de = { ab b1 [2] 8f bf [2] a4 93 [2] 8a b1 [2] 9e aa [2] 91 b0 [2] 8f ad [2] 8d ac [2] 96 aa [2] 8a ad [2] 96 82 }

  condition:
    any of them
}