rule TTP_XOR_QUAD_CurrentVersionRun_6c07 {
  strings:
    $key_6c07 = { 3f 68 [2] 1b 66 [2] 30 4a [2] 1e 68 [2] 0a 73 [2] 05 69 [2] 1b 74 [2] 19 75 [2] 02 73 [2] 1e 74 [2] 02 5b }

  condition:
    any of them
}