rule TTP_XOR_QUAD_CurrentVersionRun_0740 {
  strings:
    $key_0740 = { 54 2f [2] 70 21 [2] 5b 0d [2] 75 2f [2] 61 34 [2] 6e 2e [2] 70 33 [2] 72 32 [2] 69 34 [2] 75 33 [2] 69 1c }

  condition:
    any of them
}