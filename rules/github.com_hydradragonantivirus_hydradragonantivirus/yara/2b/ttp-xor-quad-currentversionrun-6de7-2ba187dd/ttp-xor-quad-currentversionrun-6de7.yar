rule TTP_XOR_QUAD_CurrentVersionRun_6de7 {
  strings:
    $key_6de7 = { 3e 88 [2] 1a 86 [2] 31 aa [2] 1f 88 [2] 0b 93 [2] 04 89 [2] 1a 94 [2] 18 95 [2] 03 93 [2] 1f 94 [2] 03 bb }

  condition:
    any of them
}