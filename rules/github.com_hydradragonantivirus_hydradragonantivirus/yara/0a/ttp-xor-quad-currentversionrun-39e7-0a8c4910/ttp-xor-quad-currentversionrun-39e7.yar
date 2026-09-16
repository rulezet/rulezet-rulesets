rule TTP_XOR_QUAD_CurrentVersionRun_39e7 {
  strings:
    $key_39e7 = { 6a 88 [2] 4e 86 [2] 65 aa [2] 4b 88 [2] 5f 93 [2] 50 89 [2] 4e 94 [2] 4c 95 [2] 57 93 [2] 4b 94 [2] 57 bb }

  condition:
    any of them
}