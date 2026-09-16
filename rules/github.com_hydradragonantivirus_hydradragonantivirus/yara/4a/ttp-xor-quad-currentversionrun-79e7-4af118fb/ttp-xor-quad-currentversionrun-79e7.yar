rule TTP_XOR_QUAD_CurrentVersionRun_79e7 {
  strings:
    $key_79e7 = { 2a 88 [2] 0e 86 [2] 25 aa [2] 0b 88 [2] 1f 93 [2] 10 89 [2] 0e 94 [2] 0c 95 [2] 17 93 [2] 0b 94 [2] 17 bb }

  condition:
    any of them
}