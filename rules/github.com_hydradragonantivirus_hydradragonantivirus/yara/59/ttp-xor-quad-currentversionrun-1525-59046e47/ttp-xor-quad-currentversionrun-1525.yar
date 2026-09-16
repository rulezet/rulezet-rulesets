rule TTP_XOR_QUAD_CurrentVersionRun_1525 {
  strings:
    $key_1525 = { 46 4a [2] 62 44 [2] 49 68 [2] 67 4a [2] 73 51 [2] 7c 4b [2] 62 56 [2] 60 57 [2] 7b 51 [2] 67 56 [2] 7b 79 }

  condition:
    any of them
}