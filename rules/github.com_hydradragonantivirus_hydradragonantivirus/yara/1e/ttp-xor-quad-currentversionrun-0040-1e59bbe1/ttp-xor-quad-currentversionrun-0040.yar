rule TTP_XOR_QUAD_CurrentVersionRun_0040 {
  strings:
    $key_0040 = { 53 2f [2] 77 21 [2] 5c 0d [2] 72 2f [2] 66 34 [2] 69 2e [2] 77 33 [2] 75 32 [2] 6e 34 [2] 72 33 [2] 6e 1c }

  condition:
    any of them
}