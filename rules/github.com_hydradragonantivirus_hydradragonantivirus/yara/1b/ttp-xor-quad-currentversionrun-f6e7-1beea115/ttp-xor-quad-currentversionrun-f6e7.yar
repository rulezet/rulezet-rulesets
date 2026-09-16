rule TTP_XOR_QUAD_CurrentVersionRun_f6e7 {
  strings:
    $key_f6e7 = { a5 88 [2] 81 86 [2] aa aa [2] 84 88 [2] 90 93 [2] 9f 89 [2] 81 94 [2] 83 95 [2] 98 93 [2] 84 94 [2] 98 bb }

  condition:
    any of them
}