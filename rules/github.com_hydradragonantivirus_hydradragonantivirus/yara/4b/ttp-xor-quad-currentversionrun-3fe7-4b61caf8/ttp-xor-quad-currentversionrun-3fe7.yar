rule TTP_XOR_QUAD_CurrentVersionRun_3fe7 {
  strings:
    $key_3fe7 = { 6c 88 [2] 48 86 [2] 63 aa [2] 4d 88 [2] 59 93 [2] 56 89 [2] 48 94 [2] 4a 95 [2] 51 93 [2] 4d 94 [2] 51 bb }

  condition:
    any of them
}