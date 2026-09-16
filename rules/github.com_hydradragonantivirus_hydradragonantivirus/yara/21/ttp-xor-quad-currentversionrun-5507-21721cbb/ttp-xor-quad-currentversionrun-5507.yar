rule TTP_XOR_QUAD_CurrentVersionRun_5507 {
  strings:
    $key_5507 = { 06 68 [2] 22 66 [2] 09 4a [2] 27 68 [2] 33 73 [2] 3c 69 [2] 22 74 [2] 20 75 [2] 3b 73 [2] 27 74 [2] 3b 5b }

  condition:
    any of them
}