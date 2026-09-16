rule TTP_XOR_QUAD_CurrentVersionRun_1ce7 {
  strings:
    $key_1ce7 = { 4f 88 [2] 6b 86 [2] 40 aa [2] 6e 88 [2] 7a 93 [2] 75 89 [2] 6b 94 [2] 69 95 [2] 72 93 [2] 6e 94 [2] 72 bb }

  condition:
    any of them
}