rule TTP_XOR_QUAD_CurrentVersionRun_0947 {
  strings:
    $key_0947 = { 5a 28 [2] 7e 26 [2] 55 0a [2] 7b 28 [2] 6f 33 [2] 60 29 [2] 7e 34 [2] 7c 35 [2] 67 33 [2] 7b 34 [2] 67 1b }

  condition:
    any of them
}