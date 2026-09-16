rule TTP_XOR_QUAD_CurrentVersionRun_6607 {
  strings:
    $key_6607 = { 35 68 [2] 11 66 [2] 3a 4a [2] 14 68 [2] 00 73 [2] 0f 69 [2] 11 74 [2] 13 75 [2] 08 73 [2] 14 74 [2] 08 5b }

  condition:
    any of them
}