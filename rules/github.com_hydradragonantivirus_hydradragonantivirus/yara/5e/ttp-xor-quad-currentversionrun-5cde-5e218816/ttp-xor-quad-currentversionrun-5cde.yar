rule TTP_XOR_QUAD_CurrentVersionRun_5cde {
  strings:
    $key_5cde = { 0f b1 [2] 2b bf [2] 00 93 [2] 2e b1 [2] 3a aa [2] 35 b0 [2] 2b ad [2] 29 ac [2] 32 aa [2] 2e ad [2] 32 82 }

  condition:
    any of them
}