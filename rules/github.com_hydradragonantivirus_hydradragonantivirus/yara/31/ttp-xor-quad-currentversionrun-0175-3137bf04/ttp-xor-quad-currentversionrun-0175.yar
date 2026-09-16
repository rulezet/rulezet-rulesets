rule TTP_XOR_QUAD_CurrentVersionRun_0175 {
  strings:
    $key_0175 = { 52 1a [2] 76 14 [2] 5d 38 [2] 73 1a [2] 67 01 [2] 68 1b [2] 76 06 [2] 74 07 [2] 6f 01 [2] 73 06 [2] 6f 29 }

  condition:
    any of them
}