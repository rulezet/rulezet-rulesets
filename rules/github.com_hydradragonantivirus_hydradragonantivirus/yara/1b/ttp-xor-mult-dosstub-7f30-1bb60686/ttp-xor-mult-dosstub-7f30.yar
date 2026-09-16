rule TTP_XOR_MULT_DOSStub_7f30 {
  strings:
    $key_7f30 = { 2b 58 [2] 5f 40 [2] 18 42 [2] 5f 53 [2] 11 5f [2] 1d 55 [2] 0a 5e [2] 11 10 [2] 2c }

  condition:
    any of them
}