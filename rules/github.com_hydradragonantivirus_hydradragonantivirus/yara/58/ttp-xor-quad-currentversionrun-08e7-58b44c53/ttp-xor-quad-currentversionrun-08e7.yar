rule TTP_XOR_QUAD_CurrentVersionRun_08e7 {
  strings:
    $key_08e7 = { 5b 88 [2] 7f 86 [2] 54 aa [2] 7a 88 [2] 6e 93 [2] 61 89 [2] 7f 94 [2] 7d 95 [2] 66 93 [2] 7a 94 [2] 66 bb }

  condition:
    any of them
}