rule TTP_XOR_QUAD_CurrentVersionRun_6d07 {
  strings:
    $key_6d07 = { 3e 68 [2] 1a 66 [2] 31 4a [2] 1f 68 [2] 0b 73 [2] 04 69 [2] 1a 74 [2] 18 75 [2] 03 73 [2] 1f 74 [2] 03 5b }

  condition:
    any of them
}