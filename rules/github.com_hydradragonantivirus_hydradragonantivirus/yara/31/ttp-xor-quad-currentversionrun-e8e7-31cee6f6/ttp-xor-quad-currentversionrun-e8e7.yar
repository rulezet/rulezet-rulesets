rule TTP_XOR_QUAD_CurrentVersionRun_e8e7 {
  strings:
    $key_e8e7 = { bb 88 [2] 9f 86 [2] b4 aa [2] 9a 88 [2] 8e 93 [2] 81 89 [2] 9f 94 [2] 9d 95 [2] 86 93 [2] 9a 94 [2] 86 bb }

  condition:
    any of them
}