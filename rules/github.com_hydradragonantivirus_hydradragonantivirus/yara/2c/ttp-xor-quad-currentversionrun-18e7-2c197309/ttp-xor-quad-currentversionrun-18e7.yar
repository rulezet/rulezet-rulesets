rule TTP_XOR_QUAD_CurrentVersionRun_18e7 {
  strings:
    $key_18e7 = { 4b 88 [2] 6f 86 [2] 44 aa [2] 6a 88 [2] 7e 93 [2] 71 89 [2] 6f 94 [2] 6d 95 [2] 76 93 [2] 6a 94 [2] 76 bb }

  condition:
    any of them
}