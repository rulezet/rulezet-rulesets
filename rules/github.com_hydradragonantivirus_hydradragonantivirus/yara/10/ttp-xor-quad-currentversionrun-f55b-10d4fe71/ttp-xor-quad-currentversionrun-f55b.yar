rule TTP_XOR_QUAD_CurrentVersionRun_f55b {
  strings:
    $key_f55b = { a6 34 [2] 82 3a [2] a9 16 [2] 87 34 [2] 93 2f [2] 9c 35 [2] 82 28 [2] 80 29 [2] 9b 2f [2] 87 28 [2] 9b 07 }

  condition:
    any of them
}