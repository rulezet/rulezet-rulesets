rule TTP_XOR_QUAD_CurrentVersionRun_1a07 {
  strings:
    $key_1a07 = { 49 68 [2] 6d 66 [2] 46 4a [2] 68 68 [2] 7c 73 [2] 73 69 [2] 6d 74 [2] 6f 75 [2] 74 73 [2] 68 74 [2] 74 5b }

  condition:
    any of them
}