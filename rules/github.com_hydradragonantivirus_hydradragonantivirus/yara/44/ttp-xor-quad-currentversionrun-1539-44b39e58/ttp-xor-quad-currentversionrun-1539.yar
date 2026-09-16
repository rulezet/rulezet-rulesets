rule TTP_XOR_QUAD_CurrentVersionRun_1539 {
  strings:
    $key_1539 = { 46 56 [2] 62 58 [2] 49 74 [2] 67 56 [2] 73 4d [2] 7c 57 [2] 62 4a [2] 60 4b [2] 7b 4d [2] 67 4a [2] 7b 65 }

  condition:
    any of them
}