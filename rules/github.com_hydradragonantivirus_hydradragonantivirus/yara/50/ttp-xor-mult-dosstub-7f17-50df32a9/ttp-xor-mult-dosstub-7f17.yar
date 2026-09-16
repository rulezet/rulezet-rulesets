rule TTP_XOR_MULT_DOSStub_7f17 {
  strings:
    $key_7f17 = { 2b 7f [2] 5f 67 [2] 18 65 [2] 5f 74 [2] 11 78 [2] 1d 72 [2] 0a 79 [2] 11 37 [2] 2c }

  condition:
    any of them
}