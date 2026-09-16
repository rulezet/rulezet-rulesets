rule TTP_XOR_QUAD_CurrentVersionRun_4bde {
  strings:
    $key_4bde = { 18 b1 [2] 3c bf [2] 17 93 [2] 39 b1 [2] 2d aa [2] 22 b0 [2] 3c ad [2] 3e ac [2] 25 aa [2] 39 ad [2] 25 82 }

  condition:
    any of them
}