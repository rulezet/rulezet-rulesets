rule TTP_XOR_QUAD_CurrentVersionRun_7207 {
  strings:
    $key_7207 = { 21 68 [2] 05 66 [2] 2e 4a [2] 00 68 [2] 14 73 [2] 1b 69 [2] 05 74 [2] 07 75 [2] 1c 73 [2] 00 74 [2] 1c 5b }

  condition:
    any of them
}