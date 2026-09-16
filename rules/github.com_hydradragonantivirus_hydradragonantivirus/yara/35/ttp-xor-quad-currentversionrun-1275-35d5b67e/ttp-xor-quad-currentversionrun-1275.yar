rule TTP_XOR_QUAD_CurrentVersionRun_1275 {
  strings:
    $key_1275 = { 41 1a [2] 65 14 [2] 4e 38 [2] 60 1a [2] 74 01 [2] 7b 1b [2] 65 06 [2] 67 07 [2] 7c 01 [2] 60 06 [2] 7c 29 }

  condition:
    any of them
}