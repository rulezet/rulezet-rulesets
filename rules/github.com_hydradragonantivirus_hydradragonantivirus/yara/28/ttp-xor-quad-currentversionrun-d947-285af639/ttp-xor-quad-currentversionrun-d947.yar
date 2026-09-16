rule TTP_XOR_QUAD_CurrentVersionRun_d947 {
  strings:
    $key_d947 = { 8a 28 [2] ae 26 [2] 85 0a [2] ab 28 [2] bf 33 [2] b0 29 [2] ae 34 [2] ac 35 [2] b7 33 [2] ab 34 [2] b7 1b }

  condition:
    any of them
}