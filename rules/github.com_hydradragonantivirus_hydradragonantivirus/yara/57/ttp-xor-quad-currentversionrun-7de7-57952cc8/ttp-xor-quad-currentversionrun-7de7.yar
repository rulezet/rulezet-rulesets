rule TTP_XOR_QUAD_CurrentVersionRun_7de7 {
  strings:
    $key_7de7 = { 2e 88 [2] 0a 86 [2] 21 aa [2] 0f 88 [2] 1b 93 [2] 14 89 [2] 0a 94 [2] 08 95 [2] 13 93 [2] 0f 94 [2] 13 bb }

  condition:
    any of them
}