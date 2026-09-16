rule TTP_XOR_QUAD_CurrentVersionRun_4cde {
  strings:
    $key_4cde = { 1f b1 [2] 3b bf [2] 10 93 [2] 3e b1 [2] 2a aa [2] 25 b0 [2] 3b ad [2] 39 ac [2] 22 aa [2] 3e ad [2] 22 82 }

  condition:
    any of them
}