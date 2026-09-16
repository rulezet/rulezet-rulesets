rule TTP_XOR_MULT_DOSStub_4241 {
  strings:
    $key_4241 = { 16 29 [2] 62 31 [2] 25 33 [2] 62 22 [2] 2c 2e [2] 20 24 [2] 37 2f [2] 2c 61 [2] 11 }

  condition:
    any of them
}