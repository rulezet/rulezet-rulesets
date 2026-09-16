rule TTP_XOR_QUAD_CurrentVersionRun_3a67 {
  strings:
    $key_3a67 = { 69 08 [2] 4d 06 [2] 66 2a [2] 48 08 [2] 5c 13 [2] 53 09 [2] 4d 14 [2] 4f 15 [2] 54 13 [2] 48 14 [2] 54 3b }

  condition:
    any of them
}