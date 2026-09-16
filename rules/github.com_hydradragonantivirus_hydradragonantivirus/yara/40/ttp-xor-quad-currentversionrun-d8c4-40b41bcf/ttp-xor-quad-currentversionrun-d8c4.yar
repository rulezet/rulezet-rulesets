rule TTP_XOR_QUAD_CurrentVersionRun_d8c4 {
  strings:
    $key_d8c4 = { 8b ab [2] af a5 [2] 84 89 [2] aa ab [2] be b0 [2] b1 aa [2] af b7 [2] ad b6 [2] b6 b0 [2] aa b7 [2] b6 98 }

  condition:
    any of them
}