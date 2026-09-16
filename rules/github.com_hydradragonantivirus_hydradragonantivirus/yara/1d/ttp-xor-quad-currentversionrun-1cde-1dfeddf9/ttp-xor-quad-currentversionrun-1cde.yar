rule TTP_XOR_QUAD_CurrentVersionRun_1cde {
  strings:
    $key_1cde = { 4f b1 [2] 6b bf [2] 40 93 [2] 6e b1 [2] 7a aa [2] 75 b0 [2] 6b ad [2] 69 ac [2] 72 aa [2] 6e ad [2] 72 82 }

  condition:
    any of them
}