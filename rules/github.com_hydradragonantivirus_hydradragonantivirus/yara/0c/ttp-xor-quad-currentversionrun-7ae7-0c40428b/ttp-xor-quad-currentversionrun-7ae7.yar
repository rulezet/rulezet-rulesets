rule TTP_XOR_QUAD_CurrentVersionRun_7ae7 {
  strings:
    $key_7ae7 = { 29 88 [2] 0d 86 [2] 26 aa [2] 08 88 [2] 1c 93 [2] 13 89 [2] 0d 94 [2] 0f 95 [2] 14 93 [2] 08 94 [2] 14 bb }

  condition:
    any of them
}