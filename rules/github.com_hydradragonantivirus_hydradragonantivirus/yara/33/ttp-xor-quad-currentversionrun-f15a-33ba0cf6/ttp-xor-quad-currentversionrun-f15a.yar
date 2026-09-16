rule TTP_XOR_QUAD_CurrentVersionRun_f15a {
  strings:
    $key_f15a = { a2 35 [2] 86 3b [2] ad 17 [2] 83 35 [2] 97 2e [2] 98 34 [2] 86 29 [2] 84 28 [2] 9f 2e [2] 83 29 [2] 9f 06 }

  condition:
    any of them
}