rule TTP_XOR_QUAD_CurrentVersionRun_1224 {
  strings:
    $key_1224 = { 41 4b [2] 65 45 [2] 4e 69 [2] 60 4b [2] 74 50 [2] 7b 4a [2] 65 57 [2] 67 56 [2] 7c 50 [2] 60 57 [2] 7c 78 }

  condition:
    any of them
}