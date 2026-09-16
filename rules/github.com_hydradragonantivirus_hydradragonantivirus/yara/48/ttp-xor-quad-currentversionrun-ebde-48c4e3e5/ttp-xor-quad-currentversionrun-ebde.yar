rule TTP_XOR_QUAD_CurrentVersionRun_ebde {
  strings:
    $key_ebde = { b8 b1 [2] 9c bf [2] b7 93 [2] 99 b1 [2] 8d aa [2] 82 b0 [2] 9c ad [2] 9e ac [2] 85 aa [2] 99 ad [2] 85 82 }

  condition:
    any of them
}