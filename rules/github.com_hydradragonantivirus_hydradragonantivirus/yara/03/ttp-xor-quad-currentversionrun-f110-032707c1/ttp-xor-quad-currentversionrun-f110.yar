rule TTP_XOR_QUAD_CurrentVersionRun_f110 {
  strings:
    $key_f110 = { a2 7f [2] 86 71 [2] ad 5d [2] 83 7f [2] 97 64 [2] 98 7e [2] 86 63 [2] 84 62 [2] 9f 64 [2] 83 63 [2] 9f 4c }

  condition:
    any of them
}