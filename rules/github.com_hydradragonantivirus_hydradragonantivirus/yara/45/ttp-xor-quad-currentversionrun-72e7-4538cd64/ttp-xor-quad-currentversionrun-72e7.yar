rule TTP_XOR_QUAD_CurrentVersionRun_72e7 {
  strings:
    $key_72e7 = { 21 88 [2] 05 86 [2] 2e aa [2] 00 88 [2] 14 93 [2] 1b 89 [2] 05 94 [2] 07 95 [2] 1c 93 [2] 00 94 [2] 1c bb }

  condition:
    any of them
}