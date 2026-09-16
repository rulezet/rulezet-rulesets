rule TTP_XOR_QUAD_CurrentVersionRun_dfc4 {
  strings:
    $key_dfc4 = { 8c ab [2] a8 a5 [2] 83 89 [2] ad ab [2] b9 b0 [2] b6 aa [2] a8 b7 [2] aa b6 [2] b1 b0 [2] ad b7 [2] b1 98 }

  condition:
    any of them
}