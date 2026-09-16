rule TTP_XOR_QUAD_CurrentVersionRun_2264 {
  strings:
    $key_2264 = { 71 0b [2] 55 05 [2] 7e 29 [2] 50 0b [2] 44 10 [2] 4b 0a [2] 55 17 [2] 57 16 [2] 4c 10 [2] 50 17 [2] 4c 38 }

  condition:
    any of them
}