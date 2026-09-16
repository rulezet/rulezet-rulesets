rule TTP_XOR_QUAD_CurrentVersionRun_f57b {
  strings:
    $key_f57b = { a6 14 [2] 82 1a [2] a9 36 [2] 87 14 [2] 93 0f [2] 9c 15 [2] 82 08 [2] 80 09 [2] 9b 0f [2] 87 08 [2] 9b 27 }

  condition:
    any of them
}