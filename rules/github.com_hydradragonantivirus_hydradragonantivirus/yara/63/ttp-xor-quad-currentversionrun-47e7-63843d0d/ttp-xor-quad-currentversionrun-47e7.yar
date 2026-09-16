rule TTP_XOR_QUAD_CurrentVersionRun_47e7 {
  strings:
    $key_47e7 = { 14 88 [2] 30 86 [2] 1b aa [2] 35 88 [2] 21 93 [2] 2e 89 [2] 30 94 [2] 32 95 [2] 29 93 [2] 35 94 [2] 29 bb }

  condition:
    any of them
}