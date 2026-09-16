rule TTP_XOR_QUAD_CurrentVersionRun_76e7 {
  strings:
    $key_76e7 = { 25 88 [2] 01 86 [2] 2a aa [2] 04 88 [2] 10 93 [2] 1f 89 [2] 01 94 [2] 03 95 [2] 18 93 [2] 04 94 [2] 18 bb }

  condition:
    any of them
}