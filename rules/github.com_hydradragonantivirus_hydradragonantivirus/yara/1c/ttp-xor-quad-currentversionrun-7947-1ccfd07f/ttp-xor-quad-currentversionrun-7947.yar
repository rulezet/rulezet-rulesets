rule TTP_XOR_QUAD_CurrentVersionRun_7947 {
  strings:
    $key_7947 = { 2a 28 [2] 0e 26 [2] 25 0a [2] 0b 28 [2] 1f 33 [2] 10 29 [2] 0e 34 [2] 0c 35 [2] 17 33 [2] 0b 34 [2] 17 1b }

  condition:
    any of them
}