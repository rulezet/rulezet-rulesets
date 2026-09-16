rule TTP_XOR_MULT_DOSStub_1b5c {
  strings:
    $key_1b5c = { 4f 34 [2] 3b 2c [2] 7c 2e [2] 3b 3f [2] 75 33 [2] 79 39 [2] 6e 32 [2] 75 7c [2] 48 }

  condition:
    any of them
}