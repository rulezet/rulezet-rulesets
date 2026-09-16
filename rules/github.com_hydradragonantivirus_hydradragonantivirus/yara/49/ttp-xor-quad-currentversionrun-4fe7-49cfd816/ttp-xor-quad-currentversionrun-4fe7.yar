rule TTP_XOR_QUAD_CurrentVersionRun_4fe7 {
  strings:
    $key_4fe7 = { 1c 88 [2] 38 86 [2] 13 aa [2] 3d 88 [2] 29 93 [2] 26 89 [2] 38 94 [2] 3a 95 [2] 21 93 [2] 3d 94 [2] 21 bb }

  condition:
    any of them
}