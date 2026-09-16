rule TTP_XOR_QUAD_CurrentVersionRun_7bde {
  strings:
    $key_7bde = { 28 b1 [2] 0c bf [2] 27 93 [2] 09 b1 [2] 1d aa [2] 12 b0 [2] 0c ad [2] 0e ac [2] 15 aa [2] 09 ad [2] 15 82 }

  condition:
    any of them
}