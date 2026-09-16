rule TTP_XOR_MULT_DOSStub_5947 {
  strings:
    $key_5947 = { 0d 2f [2] 79 37 [2] 3e 35 [2] 79 24 [2] 37 28 [2] 3b 22 [2] 2c 29 [2] 37 67 [2] 0a }

  condition:
    any of them
}