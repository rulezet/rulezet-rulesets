rule TTP_XOR_QUAD_CurrentVersionRun_28e7 {
  strings:
    $key_28e7 = { 7b 88 [2] 5f 86 [2] 74 aa [2] 5a 88 [2] 4e 93 [2] 41 89 [2] 5f 94 [2] 5d 95 [2] 46 93 [2] 5a 94 [2] 46 bb }

  condition:
    any of them
}