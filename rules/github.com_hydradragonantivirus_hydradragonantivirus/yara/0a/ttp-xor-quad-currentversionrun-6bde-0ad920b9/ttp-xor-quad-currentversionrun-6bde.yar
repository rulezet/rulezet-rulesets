rule TTP_XOR_QUAD_CurrentVersionRun_6bde {
  strings:
    $key_6bde = { 38 b1 [2] 1c bf [2] 37 93 [2] 19 b1 [2] 0d aa [2] 02 b0 [2] 1c ad [2] 1e ac [2] 05 aa [2] 19 ad [2] 05 82 }

  condition:
    any of them
}