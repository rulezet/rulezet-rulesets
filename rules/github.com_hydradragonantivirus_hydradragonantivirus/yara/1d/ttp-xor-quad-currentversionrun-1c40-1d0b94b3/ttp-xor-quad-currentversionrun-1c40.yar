rule TTP_XOR_QUAD_CurrentVersionRun_1c40 {
  strings:
    $key_1c40 = { 4f 2f [2] 6b 21 [2] 40 0d [2] 6e 2f [2] 7a 34 [2] 75 2e [2] 6b 33 [2] 69 32 [2] 72 34 [2] 6e 33 [2] 72 1c }

  condition:
    any of them
}