rule TTP_XOR_QUAD_CurrentVersionRun_1248 {
  strings:
    $key_1248 = { 41 27 [2] 65 29 [2] 4e 05 [2] 60 27 [2] 74 3c [2] 7b 26 [2] 65 3b [2] 67 3a [2] 7c 3c [2] 60 3b [2] 7c 14 }

  condition:
    any of them
}