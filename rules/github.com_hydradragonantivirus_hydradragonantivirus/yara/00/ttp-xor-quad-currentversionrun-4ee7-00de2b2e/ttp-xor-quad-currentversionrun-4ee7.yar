rule TTP_XOR_QUAD_CurrentVersionRun_4ee7 {
  strings:
    $key_4ee7 = { 1d 88 [2] 39 86 [2] 12 aa [2] 3c 88 [2] 28 93 [2] 27 89 [2] 39 94 [2] 3b 95 [2] 20 93 [2] 3c 94 [2] 20 bb }

  condition:
    any of them
}