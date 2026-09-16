rule TTP_XOR_QUAD_CurrentVersionRun_f140 {
  strings:
    $key_f140 = { a2 2f [2] 86 21 [2] ad 0d [2] 83 2f [2] 97 34 [2] 98 2e [2] 86 33 [2] 84 32 [2] 9f 34 [2] 83 33 [2] 9f 1c }

  condition:
    any of them
}