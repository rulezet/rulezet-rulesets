rule TTP_XOR_QUAD_CurrentVersionRun_1755 {
  strings:
    $key_1755 = { 44 3a [2] 60 34 [2] 4b 18 [2] 65 3a [2] 71 21 [2] 7e 3b [2] 60 26 [2] 62 27 [2] 79 21 [2] 65 26 [2] 79 09 }

  condition:
    any of them
}