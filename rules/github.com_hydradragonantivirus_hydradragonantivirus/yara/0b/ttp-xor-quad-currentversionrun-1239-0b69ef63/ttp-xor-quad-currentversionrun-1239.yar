rule TTP_XOR_QUAD_CurrentVersionRun_1239 {
  strings:
    $key_1239 = { 41 56 [2] 65 58 [2] 4e 74 [2] 60 56 [2] 74 4d [2] 7b 57 [2] 65 4a [2] 67 4b [2] 7c 4d [2] 60 4a [2] 7c 65 }

  condition:
    any of them
}