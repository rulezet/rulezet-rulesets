rule TTP_XOR_QUAD_CurrentVersionRun_7c07 {
  strings:
    $key_7c07 = { 2f 68 [2] 0b 66 [2] 20 4a [2] 0e 68 [2] 1a 73 [2] 15 69 [2] 0b 74 [2] 09 75 [2] 12 73 [2] 0e 74 [2] 12 5b }

  condition:
    any of them
}