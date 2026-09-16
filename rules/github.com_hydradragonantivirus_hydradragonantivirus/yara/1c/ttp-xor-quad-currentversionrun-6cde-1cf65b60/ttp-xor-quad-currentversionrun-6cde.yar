rule TTP_XOR_QUAD_CurrentVersionRun_6cde {
  strings:
    $key_6cde = { 3f b1 [2] 1b bf [2] 30 93 [2] 1e b1 [2] 0a aa [2] 05 b0 [2] 1b ad [2] 19 ac [2] 02 aa [2] 1e ad [2] 02 82 }

  condition:
    any of them
}