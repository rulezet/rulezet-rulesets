rule TTP_XOR_QUAD_CurrentVersionRun_0fe7 {
  strings:
    $key_0fe7 = { 5c 88 [2] 78 86 [2] 53 aa [2] 7d 88 [2] 69 93 [2] 66 89 [2] 78 94 [2] 7a 95 [2] 61 93 [2] 7d 94 [2] 61 bb }

  condition:
    any of them
}