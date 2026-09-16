rule TTP_XOR_QUAD_CurrentVersionRun_06e7 {
  strings:
    $key_06e7 = { 55 88 [2] 71 86 [2] 5a aa [2] 74 88 [2] 60 93 [2] 6f 89 [2] 71 94 [2] 73 95 [2] 68 93 [2] 74 94 [2] 68 bb }

  condition:
    any of them
}