rule TTP_XOR_MULT_DOSStub_5956 {
  strings:
    $key_5956 = { 0d 3e [2] 79 26 [2] 3e 24 [2] 79 35 [2] 37 39 [2] 3b 33 [2] 2c 38 [2] 37 76 [2] 0a }

  condition:
    any of them
}