rule TTP_XOR_QUAD_CurrentVersionRun_01e7 {
  strings:
    $key_01e7 = { 52 88 [2] 76 86 [2] 5d aa [2] 73 88 [2] 67 93 [2] 68 89 [2] 76 94 [2] 74 95 [2] 6f 93 [2] 73 94 [2] 6f bb }

  condition:
    any of them
}