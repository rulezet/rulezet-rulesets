rule TTP_XOR_QUAD_CurrentVersionRun_1507 {
  strings:
    $key_1507 = { 46 68 [2] 62 66 [2] 49 4a [2] 67 68 [2] 73 73 [2] 7c 69 [2] 62 74 [2] 60 75 [2] 7b 73 [2] 67 74 [2] 7b 5b }

  condition:
    any of them
}