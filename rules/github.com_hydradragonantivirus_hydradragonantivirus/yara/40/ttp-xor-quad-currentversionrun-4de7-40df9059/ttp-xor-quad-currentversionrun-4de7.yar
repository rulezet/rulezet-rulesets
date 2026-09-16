rule TTP_XOR_QUAD_CurrentVersionRun_4de7 {
  strings:
    $key_4de7 = { 1e 88 [2] 3a 86 [2] 11 aa [2] 3f 88 [2] 2b 93 [2] 24 89 [2] 3a 94 [2] 38 95 [2] 23 93 [2] 3f 94 [2] 23 bb }

  condition:
    any of them
}