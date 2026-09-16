rule TTP_XOR_QUAD_CurrentVersionRun_07e7 {
  strings:
    $key_07e7 = { 54 88 [2] 70 86 [2] 5b aa [2] 75 88 [2] 61 93 [2] 6e 89 [2] 70 94 [2] 72 95 [2] 69 93 [2] 75 94 [2] 69 bb }

  condition:
    any of them
}