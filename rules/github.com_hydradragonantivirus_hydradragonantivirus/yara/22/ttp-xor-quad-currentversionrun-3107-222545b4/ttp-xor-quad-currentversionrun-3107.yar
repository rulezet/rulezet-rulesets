rule TTP_XOR_QUAD_CurrentVersionRun_3107 {
  strings:
    $key_3107 = { 62 68 [2] 46 66 [2] 6d 4a [2] 43 68 [2] 57 73 [2] 58 69 [2] 46 74 [2] 44 75 [2] 5f 73 [2] 43 74 [2] 5f 5b }

  condition:
    any of them
}