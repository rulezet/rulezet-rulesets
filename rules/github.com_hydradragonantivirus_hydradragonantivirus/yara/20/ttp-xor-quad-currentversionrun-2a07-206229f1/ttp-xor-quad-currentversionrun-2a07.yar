rule TTP_XOR_QUAD_CurrentVersionRun_2a07 {
  strings:
    $key_2a07 = { 79 68 [2] 5d 66 [2] 76 4a [2] 58 68 [2] 4c 73 [2] 43 69 [2] 5d 74 [2] 5f 75 [2] 44 73 [2] 58 74 [2] 44 5b }

  condition:
    any of them
}