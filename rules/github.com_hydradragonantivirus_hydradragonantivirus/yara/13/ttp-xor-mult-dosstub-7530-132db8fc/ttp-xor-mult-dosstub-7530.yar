rule TTP_XOR_MULT_DOSStub_7530 {
  strings:
    $key_7530 = { 21 58 [2] 55 40 [2] 12 42 [2] 55 53 [2] 1b 5f [2] 17 55 [2] 00 5e [2] 1b 10 [2] 26 }

  condition:
    any of them
}