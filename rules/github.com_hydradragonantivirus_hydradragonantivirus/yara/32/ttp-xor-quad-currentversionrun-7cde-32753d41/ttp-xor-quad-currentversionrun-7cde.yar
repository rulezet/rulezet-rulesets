rule TTP_XOR_QUAD_CurrentVersionRun_7cde {
  strings:
    $key_7cde = { 2f b1 [2] 0b bf [2] 20 93 [2] 0e b1 [2] 1a aa [2] 15 b0 [2] 0b ad [2] 09 ac [2] 12 aa [2] 0e ad [2] 12 82 }

  condition:
    any of them
}