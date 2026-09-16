rule TTP_XOR_MULT_DOSStub_7f46 {
  strings:
    $key_7f46 = { 2b 2e [2] 5f 36 [2] 18 34 [2] 5f 25 [2] 11 29 [2] 1d 23 [2] 0a 28 [2] 11 66 [2] 2c }

  condition:
    any of them
}