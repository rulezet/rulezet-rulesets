rule TTP_XOR_QUAD_CurrentVersionRun_fbe7 {
  strings:
    $key_fbe7 = { a8 88 [2] 8c 86 [2] a7 aa [2] 89 88 [2] 9d 93 [2] 92 89 [2] 8c 94 [2] 8e 95 [2] 95 93 [2] 89 94 [2] 95 bb }

  condition:
    any of them
}