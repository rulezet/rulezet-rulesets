rule TTP_XOR_QUAD_CurrentVersionRun_3967 {
  strings:
    $key_3967 = { 6a 08 [2] 4e 06 [2] 65 2a [2] 4b 08 [2] 5f 13 [2] 50 09 [2] 4e 14 [2] 4c 15 [2] 57 13 [2] 4b 14 [2] 57 3b }

  condition:
    any of them
}