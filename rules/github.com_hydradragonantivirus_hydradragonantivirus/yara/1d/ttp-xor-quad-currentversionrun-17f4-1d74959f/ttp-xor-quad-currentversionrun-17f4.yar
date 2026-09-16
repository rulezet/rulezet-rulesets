rule TTP_XOR_QUAD_CurrentVersionRun_17f4 {
  strings:
    $key_17f4 = { 44 9b [2] 60 95 [2] 4b b9 [2] 65 9b [2] 71 80 [2] 7e 9a [2] 60 87 [2] 62 86 [2] 79 80 [2] 65 87 [2] 79 a8 }

  condition:
    any of them
}