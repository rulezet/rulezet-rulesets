rule TTP_XOR_QUAD_CurrentVersionRun_75e7 {
  strings:
    $key_75e7 = { 26 88 [2] 02 86 [2] 29 aa [2] 07 88 [2] 13 93 [2] 1c 89 [2] 02 94 [2] 00 95 [2] 1b 93 [2] 07 94 [2] 1b bb }

  condition:
    any of them
}