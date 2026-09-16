rule TTP_XOR_QUAD_CurrentVersionRun_38de {
  strings:
    $key_38de = { 6b b1 [2] 4f bf [2] 64 93 [2] 4a b1 [2] 5e aa [2] 51 b0 [2] 4f ad [2] 4d ac [2] 56 aa [2] 4a ad [2] 56 82 }

  condition:
    any of them
}