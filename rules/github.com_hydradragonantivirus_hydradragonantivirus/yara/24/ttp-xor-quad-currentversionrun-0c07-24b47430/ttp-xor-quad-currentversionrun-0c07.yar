rule TTP_XOR_QUAD_CurrentVersionRun_0c07 {
  strings:
    $key_0c07 = { 5f 68 [2] 7b 66 [2] 50 4a [2] 7e 68 [2] 6a 73 [2] 65 69 [2] 7b 74 [2] 79 75 [2] 62 73 [2] 7e 74 [2] 62 5b }

  condition:
    any of them
}