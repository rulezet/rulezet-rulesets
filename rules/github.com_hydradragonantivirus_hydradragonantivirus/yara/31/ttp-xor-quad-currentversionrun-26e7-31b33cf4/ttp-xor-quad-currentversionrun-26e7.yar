rule TTP_XOR_QUAD_CurrentVersionRun_26e7 {
  strings:
    $key_26e7 = { 75 88 [2] 51 86 [2] 7a aa [2] 54 88 [2] 40 93 [2] 4f 89 [2] 51 94 [2] 53 95 [2] 48 93 [2] 54 94 [2] 48 bb }

  condition:
    any of them
}