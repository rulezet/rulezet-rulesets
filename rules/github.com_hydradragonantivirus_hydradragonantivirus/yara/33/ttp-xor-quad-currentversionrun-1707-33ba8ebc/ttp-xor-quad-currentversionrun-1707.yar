rule TTP_XOR_QUAD_CurrentVersionRun_1707 {
  strings:
    $key_1707 = { 44 68 [2] 60 66 [2] 4b 4a [2] 65 68 [2] 71 73 [2] 7e 69 [2] 60 74 [2] 62 75 [2] 79 73 [2] 65 74 [2] 79 5b }

  condition:
    any of them
}