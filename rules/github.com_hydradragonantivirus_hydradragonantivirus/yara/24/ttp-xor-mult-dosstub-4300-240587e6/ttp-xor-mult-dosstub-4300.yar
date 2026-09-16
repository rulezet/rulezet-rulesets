rule TTP_XOR_MULT_DOSStub_4300 {
  strings:
    $key_4300 = { 17 68 [2] 63 70 [2] 24 72 [2] 63 63 [2] 2d 6f [2] 21 65 [2] 36 6e [2] 2d 20 [2] 10 }

  condition:
    any of them
}