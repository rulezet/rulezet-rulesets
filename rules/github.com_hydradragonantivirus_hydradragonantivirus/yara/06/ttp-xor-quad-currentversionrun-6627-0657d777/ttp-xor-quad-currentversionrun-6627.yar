rule TTP_XOR_QUAD_CurrentVersionRun_6627 {
  strings:
    $key_6627 = { 35 48 [2] 11 46 [2] 3a 6a [2] 14 48 [2] 00 53 [2] 0f 49 [2] 11 54 [2] 13 55 [2] 08 53 [2] 14 54 [2] 08 7b }

  condition:
    any of them
}