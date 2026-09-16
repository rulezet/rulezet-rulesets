rule TTP_XOR_QUAD_CurrentVersionRun_f53b {
  strings:
    $key_f53b = { a6 54 [2] 82 5a [2] a9 76 [2] 87 54 [2] 93 4f [2] 9c 55 [2] 82 48 [2] 80 49 [2] 9b 4f [2] 87 48 [2] 9b 67 }

  condition:
    any of them
}