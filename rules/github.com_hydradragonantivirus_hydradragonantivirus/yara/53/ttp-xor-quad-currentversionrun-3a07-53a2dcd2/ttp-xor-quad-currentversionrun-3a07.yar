rule TTP_XOR_QUAD_CurrentVersionRun_3a07 {
  strings:
    $key_3a07 = { 69 68 [2] 4d 66 [2] 66 4a [2] 48 68 [2] 5c 73 [2] 53 69 [2] 4d 74 [2] 4f 75 [2] 54 73 [2] 48 74 [2] 54 5b }

  condition:
    any of them
}