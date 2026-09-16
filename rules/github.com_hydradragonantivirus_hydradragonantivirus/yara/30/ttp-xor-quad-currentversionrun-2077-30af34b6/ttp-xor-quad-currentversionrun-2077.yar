rule TTP_XOR_QUAD_CurrentVersionRun_2077 {
  strings:
    $key_2077 = { 73 18 [2] 57 16 [2] 7c 3a [2] 52 18 [2] 46 03 [2] 49 19 [2] 57 04 [2] 55 05 [2] 4e 03 [2] 52 04 [2] 4e 2b }

  condition:
    any of them
}