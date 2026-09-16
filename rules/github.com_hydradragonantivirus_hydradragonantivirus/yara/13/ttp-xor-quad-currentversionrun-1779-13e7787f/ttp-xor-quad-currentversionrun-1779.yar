rule TTP_XOR_QUAD_CurrentVersionRun_1779 {
  strings:
    $key_1779 = { 44 16 [2] 60 18 [2] 4b 34 [2] 65 16 [2] 71 0d [2] 7e 17 [2] 60 0a [2] 62 0b [2] 79 0d [2] 65 0a [2] 79 25 }

  condition:
    any of them
}