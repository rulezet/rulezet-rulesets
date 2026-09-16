rule TTP_XOR_QUAD_CurrentVersionRun_3947 {
  strings:
    $key_3947 = { 6a 28 [2] 4e 26 [2] 65 0a [2] 4b 28 [2] 5f 33 [2] 50 29 [2] 4e 34 [2] 4c 35 [2] 57 33 [2] 4b 34 [2] 57 1b }

  condition:
    any of them
}