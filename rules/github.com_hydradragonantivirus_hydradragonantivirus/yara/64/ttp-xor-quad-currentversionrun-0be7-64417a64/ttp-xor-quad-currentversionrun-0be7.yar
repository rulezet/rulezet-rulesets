rule TTP_XOR_QUAD_CurrentVersionRun_0be7 {
  strings:
    $key_0be7 = { 58 88 [2] 7c 86 [2] 57 aa [2] 79 88 [2] 6d 93 [2] 62 89 [2] 7c 94 [2] 7e 95 [2] 65 93 [2] 79 94 [2] 65 bb }

  condition:
    any of them
}