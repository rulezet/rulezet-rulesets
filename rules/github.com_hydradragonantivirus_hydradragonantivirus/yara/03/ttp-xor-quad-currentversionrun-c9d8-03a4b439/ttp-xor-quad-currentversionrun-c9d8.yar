rule TTP_XOR_QUAD_CurrentVersionRun_c9d8 {
  strings:
    $key_c9d8 = { 9a b7 [2] be b9 [2] 95 95 [2] bb b7 [2] af ac [2] a0 b6 [2] be ab [2] bc aa [2] a7 ac [2] bb ab [2] a7 84 }

  condition:
    any of them
}