rule TTP_XOR_QUAD_CurrentVersionRun_38e7 {
  strings:
    $key_38e7 = { 6b 88 [2] 4f 86 [2] 64 aa [2] 4a 88 [2] 5e 93 [2] 51 89 [2] 4f 94 [2] 4d 95 [2] 56 93 [2] 4a 94 [2] 56 bb }

  condition:
    any of them
}