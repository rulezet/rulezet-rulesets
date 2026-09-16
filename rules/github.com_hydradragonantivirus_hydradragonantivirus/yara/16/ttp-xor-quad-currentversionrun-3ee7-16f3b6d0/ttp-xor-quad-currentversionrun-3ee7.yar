rule TTP_XOR_QUAD_CurrentVersionRun_3ee7 {
  strings:
    $key_3ee7 = { 6d 88 [2] 49 86 [2] 62 aa [2] 4c 88 [2] 58 93 [2] 57 89 [2] 49 94 [2] 4b 95 [2] 50 93 [2] 4c 94 [2] 50 bb }

  condition:
    any of them
}