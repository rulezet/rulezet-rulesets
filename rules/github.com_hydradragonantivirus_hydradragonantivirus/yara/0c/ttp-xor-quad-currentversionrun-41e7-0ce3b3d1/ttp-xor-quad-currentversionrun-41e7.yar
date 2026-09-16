rule TTP_XOR_QUAD_CurrentVersionRun_41e7 {
  strings:
    $key_41e7 = { 12 88 [2] 36 86 [2] 1d aa [2] 33 88 [2] 27 93 [2] 28 89 [2] 36 94 [2] 34 95 [2] 2f 93 [2] 33 94 [2] 2f bb }

  condition:
    any of them
}