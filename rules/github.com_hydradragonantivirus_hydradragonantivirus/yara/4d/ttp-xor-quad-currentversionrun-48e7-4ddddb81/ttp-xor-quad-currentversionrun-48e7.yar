rule TTP_XOR_QUAD_CurrentVersionRun_48e7 {
  strings:
    $key_48e7 = { 1b 88 [2] 3f 86 [2] 14 aa [2] 3a 88 [2] 2e 93 [2] 21 89 [2] 3f 94 [2] 3d 95 [2] 26 93 [2] 3a 94 [2] 26 bb }

  condition:
    any of them
}