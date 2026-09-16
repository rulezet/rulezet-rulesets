rule TTP_XOR_QUAD_CurrentVersionRun_d867 {
  strings:
    $key_d867 = { 8b 08 [2] af 06 [2] 84 2a [2] aa 08 [2] be 13 [2] b1 09 [2] af 14 [2] ad 15 [2] b6 13 [2] aa 14 [2] b6 3b }

  condition:
    any of them
}