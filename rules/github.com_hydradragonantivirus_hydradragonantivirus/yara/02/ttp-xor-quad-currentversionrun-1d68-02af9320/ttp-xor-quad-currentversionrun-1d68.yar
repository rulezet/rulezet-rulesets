rule TTP_XOR_QUAD_CurrentVersionRun_1d68 {
  strings:
    $key_1d68 = { 4e 07 [2] 6a 09 [2] 41 25 [2] 6f 07 [2] 7b 1c [2] 74 06 [2] 6a 1b [2] 68 1a [2] 73 1c [2] 6f 1b [2] 73 34 }

  condition:
    any of them
}