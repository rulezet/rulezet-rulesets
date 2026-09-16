rule TTP_XOR_QUAD_CurrentVersionRun_d8c5 {
  strings:
    $key_d8c5 = { 8b aa [2] af a4 [2] 84 88 [2] aa aa [2] be b1 [2] b1 ab [2] af b6 [2] ad b7 [2] b6 b1 [2] aa b6 [2] b6 99 }

  condition:
    any of them
}