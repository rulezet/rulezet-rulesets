rule TTP_XOR_QUAD_CurrentVersionRun_5ee7 {
  strings:
    $key_5ee7 = { 0d 88 [2] 29 86 [2] 02 aa [2] 2c 88 [2] 38 93 [2] 37 89 [2] 29 94 [2] 2b 95 [2] 30 93 [2] 2c 94 [2] 30 bb }

  condition:
    any of them
}