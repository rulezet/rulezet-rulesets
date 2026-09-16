rule TTP_XOR_QUAD_CurrentVersionRun_d8d7 {
  strings:
    $key_d8d7 = { 8b b8 [2] af b6 [2] 84 9a [2] aa b8 [2] be a3 [2] b1 b9 [2] af a4 [2] ad a5 [2] b6 a3 [2] aa a4 [2] b6 8b }

  condition:
    any of them
}