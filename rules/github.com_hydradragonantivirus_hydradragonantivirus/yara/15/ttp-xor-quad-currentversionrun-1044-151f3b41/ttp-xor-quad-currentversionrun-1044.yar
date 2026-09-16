rule TTP_XOR_QUAD_CurrentVersionRun_1044 {
  strings:
    $key_1044 = { 43 2b [2] 67 25 [2] 4c 09 [2] 62 2b [2] 76 30 [2] 79 2a [2] 67 37 [2] 65 36 [2] 7e 30 [2] 62 37 [2] 7e 18 }

  condition:
    any of them
}