rule TTP_XOR_QUAD_CurrentVersionRun_09de {
  strings:
    $key_09de = { 5a b1 [2] 7e bf [2] 55 93 [2] 7b b1 [2] 6f aa [2] 60 b0 [2] 7e ad [2] 7c ac [2] 67 aa [2] 7b ad [2] 67 82 }

  condition:
    any of them
}