rule TTP_XOR_QUAD_CurrentVersionRun_d8c6 {
  strings:
    $key_d8c6 = { 8b a9 [2] af a7 [2] 84 8b [2] aa a9 [2] be b2 [2] b1 a8 [2] af b5 [2] ad b4 [2] b6 b2 [2] aa b5 [2] b6 9a }

  condition:
    any of them
}