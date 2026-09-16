rule TTP_XOR_QUAD_CurrentVersionRun_49e7 {
  strings:
    $key_49e7 = { 1a 88 [2] 3e 86 [2] 15 aa [2] 3b 88 [2] 2f 93 [2] 20 89 [2] 3e 94 [2] 3c 95 [2] 27 93 [2] 3b 94 [2] 27 bb }

  condition:
    any of them
}