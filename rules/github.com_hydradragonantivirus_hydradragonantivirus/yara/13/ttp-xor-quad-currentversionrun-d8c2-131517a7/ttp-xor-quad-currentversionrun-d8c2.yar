rule TTP_XOR_QUAD_CurrentVersionRun_d8c2 {
  strings:
    $key_d8c2 = { 8b ad [2] af a3 [2] 84 8f [2] aa ad [2] be b6 [2] b1 ac [2] af b1 [2] ad b0 [2] b6 b6 [2] aa b1 [2] b6 9e }

  condition:
    any of them
}