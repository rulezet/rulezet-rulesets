rule TTP_XOR_MULT_DOSStub_0b5c {
  strings:
    $key_0b5c = { 5f 34 [2] 2b 2c [2] 6c 2e [2] 2b 3f [2] 65 33 [2] 69 39 [2] 7e 32 [2] 65 7c [2] 58 }

  condition:
    any of them
}