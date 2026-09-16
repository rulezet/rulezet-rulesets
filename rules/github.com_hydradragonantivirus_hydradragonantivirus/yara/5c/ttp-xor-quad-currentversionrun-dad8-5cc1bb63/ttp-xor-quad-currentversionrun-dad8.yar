rule TTP_XOR_QUAD_CurrentVersionRun_dad8 {
  strings:
    $key_dad8 = { 89 b7 [2] ad b9 [2] 86 95 [2] a8 b7 [2] bc ac [2] b3 b6 [2] ad ab [2] af aa [2] b4 ac [2] a8 ab [2] b4 84 }

  condition:
    any of them
}