rule TTP_XOR_QUAD_CurrentVersionRun_0e07 {
  strings:
    $key_0e07 = { 5d 68 [2] 79 66 [2] 52 4a [2] 7c 68 [2] 68 73 [2] 67 69 [2] 79 74 [2] 7b 75 [2] 60 73 [2] 7c 74 [2] 60 5b }

  condition:
    any of them
}