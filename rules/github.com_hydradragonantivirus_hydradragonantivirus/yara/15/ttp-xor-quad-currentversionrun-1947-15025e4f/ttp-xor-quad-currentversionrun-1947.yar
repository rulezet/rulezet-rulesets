rule TTP_XOR_QUAD_CurrentVersionRun_1947 {
  strings:
    $key_1947 = { 4a 28 [2] 6e 26 [2] 45 0a [2] 6b 28 [2] 7f 33 [2] 70 29 [2] 6e 34 [2] 6c 35 [2] 77 33 [2] 6b 34 [2] 77 1b }

  condition:
    any of them
}