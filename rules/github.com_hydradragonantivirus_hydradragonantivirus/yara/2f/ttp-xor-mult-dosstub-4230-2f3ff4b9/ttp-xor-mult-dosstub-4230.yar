rule TTP_XOR_MULT_DOSStub_4230 {
  strings:
    $key_4230 = { 16 58 [2] 62 40 [2] 25 42 [2] 62 53 [2] 2c 5f [2] 20 55 [2] 37 5e [2] 2c 10 [2] 11 }

  condition:
    any of them
}