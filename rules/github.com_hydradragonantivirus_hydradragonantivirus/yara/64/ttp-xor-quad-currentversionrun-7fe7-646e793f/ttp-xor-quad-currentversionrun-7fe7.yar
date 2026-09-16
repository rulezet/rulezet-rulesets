rule TTP_XOR_QUAD_CurrentVersionRun_7fe7 {
  strings:
    $key_7fe7 = { 2c 88 [2] 08 86 [2] 23 aa [2] 0d 88 [2] 19 93 [2] 16 89 [2] 08 94 [2] 0a 95 [2] 11 93 [2] 0d 94 [2] 11 bb }

  condition:
    any of them
}