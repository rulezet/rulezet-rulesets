rule TTP_XOR_QUAD_CurrentVersionRun_75e8 {
  strings:
    $key_75e8 = { 26 87 [2] 02 89 [2] 29 a5 [2] 07 87 [2] 13 9c [2] 1c 86 [2] 02 9b [2] 00 9a [2] 1b 9c [2] 07 9b [2] 1b b4 }

  condition:
    any of them
}