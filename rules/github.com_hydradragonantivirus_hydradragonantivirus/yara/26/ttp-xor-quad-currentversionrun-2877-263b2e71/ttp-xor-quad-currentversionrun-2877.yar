rule TTP_XOR_QUAD_CurrentVersionRun_2877 {
  strings:
    $key_2877 = { 7b 18 [2] 5f 16 [2] 74 3a [2] 5a 18 [2] 4e 03 [2] 41 19 [2] 5f 04 [2] 5d 05 [2] 46 03 [2] 5a 04 [2] 46 2b }

  condition:
    any of them
}