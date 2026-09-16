rule TTP_XOR_QUAD_CurrentVersionRun_f507 {
  strings:
    $key_f507 = { a6 68 [2] 82 66 [2] a9 4a [2] 87 68 [2] 93 73 [2] 9c 69 [2] 82 74 [2] 80 75 [2] 9b 73 [2] 87 74 [2] 9b 5b }

  condition:
    any of them
}