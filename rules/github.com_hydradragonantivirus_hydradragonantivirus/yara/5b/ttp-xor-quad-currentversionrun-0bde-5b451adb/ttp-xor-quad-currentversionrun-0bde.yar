rule TTP_XOR_QUAD_CurrentVersionRun_0bde {
  strings:
    $key_0bde = { 58 b1 [2] 7c bf [2] 57 93 [2] 79 b1 [2] 6d aa [2] 62 b0 [2] 7c ad [2] 7e ac [2] 65 aa [2] 79 ad [2] 65 82 }

  condition:
    any of them
}