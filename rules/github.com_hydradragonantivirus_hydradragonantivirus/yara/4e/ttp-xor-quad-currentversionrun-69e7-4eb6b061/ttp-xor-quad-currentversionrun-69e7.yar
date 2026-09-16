rule TTP_XOR_QUAD_CurrentVersionRun_69e7 {
  strings:
    $key_69e7 = { 3a 88 [2] 1e 86 [2] 35 aa [2] 1b 88 [2] 0f 93 [2] 00 89 [2] 1e 94 [2] 1c 95 [2] 07 93 [2] 1b 94 [2] 07 bb }

  condition:
    any of them
}