rule TTP_XOR_MULT_DOSStub_0c5c {
  strings:
    $key_0c5c = { 58 34 [2] 2c 2c [2] 6b 2e [2] 2c 3f [2] 62 33 [2] 6e 39 [2] 79 32 [2] 62 7c [2] 5f }

  condition:
    any of them
}