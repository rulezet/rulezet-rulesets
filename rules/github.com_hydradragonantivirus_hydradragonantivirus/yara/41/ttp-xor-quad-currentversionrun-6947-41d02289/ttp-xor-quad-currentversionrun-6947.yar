rule TTP_XOR_QUAD_CurrentVersionRun_6947 {
  strings:
    $key_6947 = { 3a 28 [2] 1e 26 [2] 35 0a [2] 1b 28 [2] 0f 33 [2] 00 29 [2] 1e 34 [2] 1c 35 [2] 07 33 [2] 1b 34 [2] 07 1b }

  condition:
    any of them
}