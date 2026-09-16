rule TTP_XOR_QUAD_CurrentVersionRun_0e47 {
  strings:
    $key_0e47 = { 5d 28 [2] 79 26 [2] 52 0a [2] 7c 28 [2] 68 33 [2] 67 29 [2] 79 34 [2] 7b 35 [2] 60 33 [2] 7c 34 [2] 60 1b }

  condition:
    any of them
}