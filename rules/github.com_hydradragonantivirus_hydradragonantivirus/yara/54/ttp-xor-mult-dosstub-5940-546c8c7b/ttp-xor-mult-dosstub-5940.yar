rule TTP_XOR_MULT_DOSStub_5940 {
  strings:
    $key_5940 = { 0d 28 [2] 79 30 [2] 3e 32 [2] 79 23 [2] 37 2f [2] 3b 25 [2] 2c 2e [2] 37 60 [2] 0a }

  condition:
    any of them
}