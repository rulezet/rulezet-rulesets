rule TTP_XOR_QUAD_CurrentVersionRun_f15b {
  strings:
    $key_f15b = { a2 34 [2] 86 3a [2] ad 16 [2] 83 34 [2] 97 2f [2] 98 35 [2] 86 28 [2] 84 29 [2] 9f 2f [2] 83 28 [2] 9f 07 }

  condition:
    any of them
}