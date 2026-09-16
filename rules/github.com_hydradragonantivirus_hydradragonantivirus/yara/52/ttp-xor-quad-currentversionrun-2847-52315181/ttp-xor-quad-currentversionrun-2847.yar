rule TTP_XOR_QUAD_CurrentVersionRun_2847 {
  strings:
    $key_2847 = { 7b 28 [2] 5f 26 [2] 74 0a [2] 5a 28 [2] 4e 33 [2] 41 29 [2] 5f 34 [2] 5d 35 [2] 46 33 [2] 5a 34 [2] 46 1b }

  condition:
    any of them
}