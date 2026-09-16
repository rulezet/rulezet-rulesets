rule TTP_XOR_QUAD_CurrentVersionRun_7a07 {
  strings:
    $key_7a07 = { 29 68 [2] 0d 66 [2] 26 4a [2] 08 68 [2] 1c 73 [2] 13 69 [2] 0d 74 [2] 0f 75 [2] 14 73 [2] 08 74 [2] 14 5b }

  condition:
    any of them
}