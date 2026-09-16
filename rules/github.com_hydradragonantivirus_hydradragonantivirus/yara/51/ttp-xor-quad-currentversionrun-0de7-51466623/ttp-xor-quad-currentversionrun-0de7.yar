rule TTP_XOR_QUAD_CurrentVersionRun_0de7 {
  strings:
    $key_0de7 = { 5e 88 [2] 7a 86 [2] 51 aa [2] 7f 88 [2] 6b 93 [2] 64 89 [2] 7a 94 [2] 78 95 [2] 63 93 [2] 7f 94 [2] 63 bb }

  condition:
    any of them
}