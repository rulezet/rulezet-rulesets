rule TTP_XOR_QUAD_CurrentVersionRun_f527 {
  strings:
    $key_f527 = { a6 48 [2] 82 46 [2] a9 6a [2] 87 48 [2] 93 53 [2] 9c 49 [2] 82 54 [2] 80 55 [2] 9b 53 [2] 87 54 [2] 9b 7b }

  condition:
    any of them
}