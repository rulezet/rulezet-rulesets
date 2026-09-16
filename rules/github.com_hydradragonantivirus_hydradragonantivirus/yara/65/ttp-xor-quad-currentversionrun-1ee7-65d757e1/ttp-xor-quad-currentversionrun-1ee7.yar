rule TTP_XOR_QUAD_CurrentVersionRun_1ee7 {
  strings:
    $key_1ee7 = { 4d 88 [2] 69 86 [2] 42 aa [2] 6c 88 [2] 78 93 [2] 77 89 [2] 69 94 [2] 6b 95 [2] 70 93 [2] 6c 94 [2] 70 bb }

  condition:
    any of them
}