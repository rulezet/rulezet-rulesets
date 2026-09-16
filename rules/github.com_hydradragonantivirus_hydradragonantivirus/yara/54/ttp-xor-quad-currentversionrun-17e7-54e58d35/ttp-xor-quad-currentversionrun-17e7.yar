rule TTP_XOR_QUAD_CurrentVersionRun_17e7 {
  strings:
    $key_17e7 = { 44 88 [2] 60 86 [2] 4b aa [2] 65 88 [2] 71 93 [2] 7e 89 [2] 60 94 [2] 62 95 [2] 79 93 [2] 65 94 [2] 79 bb }

  condition:
    any of them
}