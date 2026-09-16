rule TTP_XOR_QUAD_CurrentVersionRun_6fe7 {
  strings:
    $key_6fe7 = { 3c 88 [2] 18 86 [2] 33 aa [2] 1d 88 [2] 09 93 [2] 06 89 [2] 18 94 [2] 1a 95 [2] 01 93 [2] 1d 94 [2] 01 bb }

  condition:
    any of them
}