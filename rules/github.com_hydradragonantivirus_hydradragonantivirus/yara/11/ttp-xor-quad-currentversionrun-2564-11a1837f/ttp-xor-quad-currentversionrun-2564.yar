rule TTP_XOR_QUAD_CurrentVersionRun_2564 {
  strings:
    $key_2564 = { 76 0b [2] 52 05 [2] 79 29 [2] 57 0b [2] 43 10 [2] 4c 0a [2] 52 17 [2] 50 16 [2] 4b 10 [2] 57 17 [2] 4b 38 }

  condition:
    any of them
}