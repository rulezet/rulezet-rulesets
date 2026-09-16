rule TTP_XOR_MULT_DOSStub_7f06 {
  strings:
    $key_7f06 = { 2b 6e [2] 5f 76 [2] 18 74 [2] 5f 65 [2] 11 69 [2] 1d 63 [2] 0a 68 [2] 11 26 [2] 2c }

  condition:
    any of them
}