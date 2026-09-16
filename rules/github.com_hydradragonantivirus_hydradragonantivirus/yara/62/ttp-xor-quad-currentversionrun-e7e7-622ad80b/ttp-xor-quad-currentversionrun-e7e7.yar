rule TTP_XOR_QUAD_CurrentVersionRun_e7e7 {
  strings:
    $key_e7e7 = { b4 88 [2] 90 86 [2] bb aa [2] 95 88 [2] 81 93 [2] 8e 89 [2] 90 94 [2] 92 95 [2] 89 93 [2] 95 94 [2] 89 bb }

  condition:
    any of them
}