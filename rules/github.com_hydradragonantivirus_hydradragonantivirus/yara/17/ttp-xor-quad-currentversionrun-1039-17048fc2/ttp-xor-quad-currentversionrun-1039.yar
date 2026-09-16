rule TTP_XOR_QUAD_CurrentVersionRun_1039 {
  strings:
    $key_1039 = { 43 56 [2] 67 58 [2] 4c 74 [2] 62 56 [2] 76 4d [2] 79 57 [2] 67 4a [2] 65 4b [2] 7e 4d [2] 62 4a [2] 7e 65 }

  condition:
    any of them
}