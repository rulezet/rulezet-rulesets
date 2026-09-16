rule TTP_XOR_QUAD_CurrentVersionRun_6be7 {
  strings:
    $key_6be7 = { 38 88 [2] 1c 86 [2] 37 aa [2] 19 88 [2] 0d 93 [2] 02 89 [2] 1c 94 [2] 1e 95 [2] 05 93 [2] 19 94 [2] 05 bb }

  condition:
    any of them
}