rule TTP_XOR_QUAD_CurrentVersionRun_c4d8 {
  strings:
    $key_c4d8 = { 97 b7 [2] b3 b9 [2] 98 95 [2] b6 b7 [2] a2 ac [2] ad b6 [2] b3 ab [2] b1 aa [2] aa ac [2] b6 ab [2] aa 84 }

  condition:
    any of them
}