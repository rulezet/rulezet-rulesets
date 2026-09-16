rule TTP_XOR_QUAD_CurrentVersionRun_1d39 {
  strings:
    $key_1d39 = { 4e 56 [2] 6a 58 [2] 41 74 [2] 6f 56 [2] 7b 4d [2] 74 57 [2] 6a 4a [2] 68 4b [2] 73 4d [2] 6f 4a [2] 73 65 }

  condition:
    any of them
}