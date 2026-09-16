rule TTP_XOR_QUAD_CurrentVersionRun_d8d6 {
  strings:
    $key_d8d6 = { 8b b9 [2] af b7 [2] 84 9b [2] aa b9 [2] be a2 [2] b1 b8 [2] af a5 [2] ad a4 [2] b6 a2 [2] aa a5 [2] b6 8a }

  condition:
    any of them
}