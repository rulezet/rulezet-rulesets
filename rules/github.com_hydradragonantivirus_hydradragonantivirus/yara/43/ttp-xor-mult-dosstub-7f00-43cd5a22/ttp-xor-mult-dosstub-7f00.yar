rule TTP_XOR_MULT_DOSStub_7f00 {
  strings:
    $key_7f00 = { 2b 68 [2] 5f 70 [2] 18 72 [2] 5f 63 [2] 11 6f [2] 1d 65 [2] 0a 6e [2] 11 20 [2] 2c }

  condition:
    any of them
}