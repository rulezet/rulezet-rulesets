rule TTP_XOR_QUAD_CurrentVersionRun_48de {
  strings:
    $key_48de = { 1b b1 [2] 3f bf [2] 14 93 [2] 3a b1 [2] 2e aa [2] 21 b0 [2] 3f ad [2] 3d ac [2] 26 aa [2] 3a ad [2] 26 82 }

  condition:
    any of them
}