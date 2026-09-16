rule TTP_XOR_QUAD_CurrentVersionRun_1064 {
  strings:
    $key_1064 = { 43 0b [2] 67 05 [2] 4c 29 [2] 62 0b [2] 76 10 [2] 79 0a [2] 67 17 [2] 65 16 [2] 7e 10 [2] 62 17 [2] 7e 38 }

  condition:
    any of them
}