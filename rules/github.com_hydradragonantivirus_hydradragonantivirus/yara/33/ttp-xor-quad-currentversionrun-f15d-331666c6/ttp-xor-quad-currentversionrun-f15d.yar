rule TTP_XOR_QUAD_CurrentVersionRun_f15d {
  strings:
    $key_f15d = { a2 32 [2] 86 3c [2] ad 10 [2] 83 32 [2] 97 29 [2] 98 33 [2] 86 2e [2] 84 2f [2] 9f 29 [2] 83 2e [2] 9f 01 }

  condition:
    any of them
}